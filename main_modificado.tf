provider "aws" {
  region = "us-east-1"
}

variable "projeto" {
  description = "Nome do projeto"
  type        = string
  default     = "VExpenses"
}

variable "candidato" {
  description = "Nome do candidato"
  type        = string
  default     = "SeuNome"
}

variable "public_key" {
    description = "public_key para acessar a instância ec2"
    type = string
}

resource "aws_key_pair" "ec2_key_pair" {
  key_name   = "${var.projeto}-${var.candidato}-key"
  public_key = var.public_key
}


resource "aws_iam_policy" "rds_access_policy" {
  name        = "${var.projeto}-${var.candidato}-rds-access-policy"
  description = "Permissões para acessar o Amazon RDS"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "rds:DescribeDBInstances",
          "rds:Connect"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role" "rds_access_role" {
  name               = "${var.projeto}-${var.candidato}-rds-access-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com" 
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_rds_policy" {
  role       = aws_iam_role.rds_access_role.name
  policy_arn = aws_iam_policy.rds_access_policy.arn
}

resource "aws_vpc" "main_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.projeto}-${var.candidato}-vpc"
  }
}

resource "aws_subnet" "main_subnet" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "${var.projeto}-${var.candidato}-subnet"
  }
}

resource "aws_internet_gateway" "main_igw" {
  vpc_id = aws_vpc.main_vpc.id

  tags = {
    Name = "${var.projeto}-${var.candidato}-igw"
  }
}

resource "aws_route_table" "main_route_table" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block = "[ENDEREÇO DE IP AUTORIZADO]"
    gateway_id = aws_internet_gateway.main_igw.id
  }

  tags = {
    Name = "${var.projeto}-${var.candidato}-route_table"
  }
}

resource "aws_route_table_association" "main_association" {
  subnet_id      = aws_subnet.main_subnet.id
  route_table_id = aws_route_table.main_route_table.id

  tags = {
    Name = "${var.projeto}-${var.candidato}-route_table_association"
  }
}

  resource "aws_security_group" "main_sg" {
  name        = "${var.projeto}-${var.candidato}-sg"
  description = "Limitar acesso SSH e saída de tráfego"
  vpc_id      = aws_vpc.main_vpc.id

  # Regras de entrada
  ingress {
    description      = "Limita o acesso via SSH"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["[ENDEREÇO DE IP AUTORIZADO]32"]
    ipv6_cidr_blocks = ["[ENDEREÇO DE IPV6 AUTORIZADO]/128"]
  }

  # Regras de saída serviços de DNS
  egress {
    description      = "Permite a saída para serviço de DNS"
    from_port        = 53
    to_port          = 53
    protocol         = "tcp"
    cidr_blocks      = ["ENDEREÇO IP DO SERVIÇO DE DNS"]
    ipv6_cidr_blocks = ["ENDEREÇO IPV6 DO SERVIÇO DE DNS"]
  }

  # Regras de saída Pacotes de Atualização HTTP
  egress {
    description      = "Permite a saída para HTTP"
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["ENDEREÇO IP DA LISTA DE PACOTES"]
    ipv6_cidr_blocks = ["ENDEREÇO IPV6 DA LISTA DE PACOTES"]
  }

 # Regras de saída Pacotes de Atualização HTTPS
  egress {
    description      = "Permite a saída para HTTP"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["ENDEREÇO IP DA LISTA DE PACOTES"]
    ipv6_cidr_blocks = ["ENDEREÇO IPV6 DA LISTA DE PACOTES"]
  }

 # Regras de saída para o Banco de Dados
  egress {
    description      = "Permite a saída para o banco de dados"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["ENDEREÇO IP DO BANCO DE DADOS"]
    ipv6_cidr_blocks = ["ENDEREÇO IPV6 DO BANCO DE DADOS"]
  }

  tags = {
    Name = "${var.projeto}-${var.candidato}-sg"
  }
}

data "aws_ami" "debian12" {
  most_recent = true

  filter {
    name   = "name"
    values = ["debian-12-amd64-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["679593333241"]
}

resource "aws_instance" "debian_ec2" {
  ami             = data.aws_ami.debian12.id
  instance_type   = "t2.micro"
  subnet_id       = aws_subnet.main_subnet.id
  key_name        = aws_key_pair.ec2_key_pair.key_name
  security_groups = [aws_security_group.main_sg.name]
  iam_instance_profile = aws_iam_role.rds_access_role.name

  associate_public_ip_address = true

  root_block_device {
    volume_size           = 20
    volume_type           = "gp2"
    delete_on_termination = true
  }

  user_data = <<-EOF
              #!/bin/bash
              apt-get update -y
              apt-get upgrade -y

              # instala o nginx
              apt-get install -y nginx

              systemctl start nginx
              systemctl enable nginx
              EOF

  tags = {
    Name = "${var.projeto}-${var.candidato}-ec2"
  }

  lifecycle {
    prevent_destroy = true
  }
}

output "ec2_public_ip" {
  description = "Endereço IP público da instância EC2"
  value       = aws_instance.debian_ec2.public_ip
}
