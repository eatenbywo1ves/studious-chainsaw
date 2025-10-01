terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
  }
  
  backend "s3" {
    bucket = "catalytic-terraform-state"
    key    = "staging/terraform.tfstate"
    region = "us-east-1"
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Environment = "staging"
      Project     = "catalytic-computing"
      ManagedBy   = "terraform"
    }
  }
}

module "vpc" {
  source = "../../modules/vpc"
  
  environment = var.environment
  vpc_cidr    = "10.1.0.0/16"
  
  availability_zones = ["${var.aws_region}a", "${var.aws_region}b", "${var.aws_region}c"]
  
  tags = {
    Environment = var.environment
  }
}

module "eks" {
  source = "../../modules/eks"
  
  environment        = var.environment
  vpc_id            = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  
  cluster_version = "1.28"
  
  node_groups = {
    main = {
      instance_types = ["t3.medium"]
      scaling_config = {
        desired_size = 2
        max_size     = 5
        min_size     = 1
      }
    }
  }
  
  tags = {
    Environment = var.environment
  }
}

module "rds" {
  source = "../../modules/rds"
  
  environment      = var.environment
  vpc_id          = module.vpc.vpc_id
  subnet_ids      = module.vpc.private_subnet_ids
  
  instance_class  = "db.t3.micro"
  allocated_storage = 20
  
  tags = {
    Environment = var.environment
  }
}

module "elasticache" {
  source = "../../modules/elasticache"
  
  environment = var.environment
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnet_ids
  
  node_type = "cache.t3.micro"
  
  tags = {
    Environment = var.environment
  }
}

module "alb" {
  source = "../../modules/alb"
  
  environment = var.environment
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.public_subnet_ids
  
  domain_name = var.domain_name
  
  tags = {
    Environment = var.environment
  }
}