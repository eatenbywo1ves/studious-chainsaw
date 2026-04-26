# Linux Deployment Execution Playbook
**Date:** October 22, 2025
**Status:** 🎯 Ready to Execute
**Estimated Time:** 2-4 hours

---

## 📋 What You Need Before Starting

### **Required:**
- ✅ Code committed and pushed to GitHub (commit: 358428cc) ✓ DONE
- ⏳ AWS account with credentials configured
- ⏳ Access to create AWS resources (EC2, RDS, etc.)
- ⏳ Terminal/SSH client (Windows Terminal, PuTTY, or WSL)
- ⏳ 2-4 hours of uninterrupted time

### **Optional (Recommended):**
- GitHub personal access token (for private repos)
- Domain name configured (staging.catalytic.dev)
- Monitoring tools (Datadog, New Relic, etc.)

---

## 🎯 Deployment Options

You have **three deployment paths**. Choose based on your infrastructure:

### **Option A: AWS EKS (Kubernetes) - Full Production Stack**
- **Time:** 2-3 hours
- **Cost:** ~$150-200/month
- **Scalability:** Excellent (auto-scaling)
- **Complexity:** High (Terraform required)
- **Best For:** Production-grade deployment

### **Option B: AWS EC2 (Simple Linux Server) - Quick Start** ⭐ **RECOMMENDED**
- **Time:** 30-60 minutes
- **Cost:** ~$20-50/month
- **Scalability:** Manual (can add load balancer later)
- **Complexity:** Low (just SSH and run script)
- **Best For:** Staging, quick validation

### **Option C: Local Linux (WSL2 or VM) - Development Testing**
- **Time:** 15-30 minutes
- **Cost:** Free
- **Scalability:** N/A (local only)
- **Complexity:** Very Low
- **Best For:** Quick validation before cloud deployment

---

## 🚀 OPTION A: AWS EKS Deployment (Full Stack)

### **Step 1: Configure AWS Credentials**

```powershell
# On Windows PowerShell:
# Install AWS CLI if not installed
# Download from: https://aws.amazon.com/cli/

# Configure credentials
aws configure

# Enter when prompted:
# AWS Access Key ID: [Your access key]
# AWS Secret Access Key: [Your secret key]
# Default region name: us-east-1
# Default output format: json

# Test credentials
aws sts get-caller-identity
```

### **Step 2: Deploy Infrastructure with Terraform**

```powershell
# Navigate to staging environment
cd C:\Users\Corbin\development\saas\terraform\environments\staging

# Initialize Terraform
terraform init

# Review what will be created
terraform plan

# Deploy infrastructure (will take 15-20 minutes)
terraform apply

# Save outputs
terraform output > staging_outputs.txt
```

**What Gets Created:**
- VPC with public/private subnets
- EKS cluster (Kubernetes)
- RDS PostgreSQL database
- ElastiCache Redis
- Application Load Balancer
- Security groups and networking

### **Step 3: Configure kubectl**

```powershell
# Get cluster connection info
aws eks update-kubeconfig --region us-east-1 --name catalytic-staging

# Verify connection
kubectl get nodes
```

### **Step 4: Deploy Application**

```powershell
# Create Kubernetes deployment
kubectl apply -f k8s/staging/

# Wait for pods to be ready
kubectl get pods -w

# Get load balancer URL
kubectl get service catalytic-saas -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
```

### **Step 5: Validate Deployment**

```powershell
# Get the load balancer URL from previous step
$LB_URL = "your-load-balancer-url.elb.amazonaws.com"

# Run validation
python validate_deployment.py --host "http://$LB_URL"

# Run load test
locust -f tests\performance\simple_loadtest.py `
  --users 1000 `
  --spawn-rate 100 `
  --run-time 180 `
  --host "http://$LB_URL" `
  --headless `
  --html eks_1k_users.html
```

---

## 🚀 OPTION B: AWS EC2 Simple Deployment ⭐ **RECOMMENDED**

This is the fastest way to validate the optimizations on Linux.

### **Step 1: Launch EC2 Instance**

```powershell
# Launch Ubuntu 22.04 instance
aws ec2 run-instances `
  --image-id ami-0c7217cdde317cfec `
  --instance-type t3.medium `
  --key-name your-key-pair `
  --security-group-ids sg-xxxxxxxx `
  --subnet-id subnet-xxxxxxxx `
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=catalytic-staging}]'

# Wait for instance to be running
aws ec2 wait instance-running --instance-ids i-xxxxxxxxx

# Get public IP
aws ec2 describe-instances --instance-ids i-xxxxxxxxx --query 'Reservations[0].Instances[0].PublicIpAddress'
```

**Or use AWS Console:**
1. Go to EC2 Dashboard
2. Click "Launch Instance"
3. Choose: Ubuntu Server 22.04 LTS
4. Instance type: t3.medium (2 vCPU, 4GB RAM)
5. Create/select key pair
6. Configure security group (allow ports 22, 80, 443, 8000)
7. Launch instance

### **Step 2: Connect via SSH**

```powershell
# From Windows PowerShell (if you have OpenSSH):
ssh -i "your-key.pem" ubuntu@ec2-xx-xx-xx-xx.compute-1.amazonaws.com

# Or use PuTTY:
# 1. Convert .pem to .ppk with PuTTYgen
# 2. Open PuTTY
# 3. Enter: ubuntu@ec2-xx-xx-xx-xx.compute-1.amazonaws.com
# 4. SSH > Auth > Browse to your .ppk file
# 5. Click Open
```

### **Step 3: Run Automated Deployment Script**

```bash
# Once connected to EC2 instance:

# Download and run deployment script
wget https://raw.githubusercontent.com/eatenbywo1ves/studious-chainsaw/feat/todo-deployment-phase-1/development/saas/LINUX_DEPLOYMENT_QUICKSTART.sh

chmod +x LINUX_DEPLOYMENT_QUICKSTART.sh

# Run with defaults (will install everything)
./LINUX_DEPLOYMENT_QUICKSTART.sh

# Script will:
# - Verify Linux platform
# - Configure ulimit -n 65536
# - Clone repository
# - Install Python dependencies
# - Start optimized server (4 workers)
# - Run health validation
# - Run baseline 100-user load test

# Wait for completion (5-10 minutes)
```

### **Step 4: Validate Deployment**

```bash
# On the EC2 instance:

# Validate with script
python validate_deployment.py --host http://localhost:8000

# Expected output: ALL VALIDATIONS PASSED ✓
```

### **Step 5: Run Production Load Test**

```bash
# On the EC2 instance:

# Install Locust (if not already installed)
pip install locust

# Run 1K user load test
locust -f tests/performance/simple_loadtest.py \
  --users 1000 \
  --spawn-rate 100 \
  --run-time 180 \
  --host http://localhost:8000 \
  --headless \
  --html staging_1k_users.html \
  --csv staging_1k_users

# Check results
cat staging_1k_users_stats.csv | tail -1

# Expected Results:
# - Success Rate: >99%
# - Median Latency: <100ms
# - 95th Percentile: <300ms
```

### **Step 6: Download Results (From Windows)**

```powershell
# Back on your Windows machine:
scp -i "your-key.pem" ubuntu@ec2-xx-xx-xx-xx.compute-1.amazonaws.com:~/staging_1k_users.html .

# Open in browser to view detailed results
start staging_1k_users.html
```

---

## 🚀 OPTION C: Local Linux (WSL2) - Quick Validation

This is the fastest option for initial validation, but won't give production-accurate load testing.

### **Step 1: Enable WSL2 on Windows**

```powershell
# Run as Administrator in PowerShell:
wsl --install

# Restart your computer

# Install Ubuntu
wsl --install -d Ubuntu-22.04

# Launch Ubuntu
wsl
```

### **Step 2: Deploy in WSL2**

```bash
# Inside WSL2 Ubuntu:

# Navigate to project (Windows drives are mounted at /mnt/)
cd /mnt/c/Users/Corbin/development/saas

# Configure ulimit
ulimit -n 65536

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start server
python start_server_optimized.py --workers 4 --port 8000 &

# Wait for startup (30 seconds)
sleep 30

# Validate
python validate_deployment.py --host http://localhost:8000

# Run moderate load test (WSL2 has limitations)
locust -f tests/performance/simple_loadtest.py \
  --users 500 \
  --spawn-rate 50 \
  --run-time 120 \
  --host http://localhost:8000 \
  --headless \
  --html wsl2_500users.html
```

**Note:** WSL2 can handle more than Windows native (no 512 FD limit), but won't match bare-metal Linux performance. Use this for validation only.

---

## ✅ Success Validation Checklist

After deploying with any option, verify these results:

### **Deployment Health:**
```bash
# 1. Health endpoint is fast
curl -w "@-" -o /dev/null -s http://your-host:8000/health <<'EOF'
    time_total:  %{time_total}\n
EOF
# Expected: <0.100 seconds (100ms)

# 2. Health endpoint is lightweight (no stats)
curl -s http://your-host:8000/health | jq .
# Expected: No "stats" field in response

# 3. No connection leaks
netstat -an | grep ':8000' | grep 'CLOSE_WAIT' | wc -l
# Expected: 0

# 4. Stats endpoint requires auth
curl -s -w "%{http_code}" -o /dev/null http://your-host:8000/api/stats
# Expected: 401 or 403
```

### **Load Test Results:**
```
✅ 1,000 User Test PASSED:
   - Success Rate: >99%
   - P50 Latency: <100ms
   - P95 Latency: <300ms
   - Throughput: 500-1,000 RPS
   - Connection Leaks: 0
```

If all checks pass → **Deployment is production-ready!** 🎉

---

## 🎓 Understanding the Results

`✶ Insight ─────────────────────────────────────`
**What the Load Test Results Tell You**

1. **Success Rate >99%**: The server is stable under load and properly handling concurrent requests without errors or timeouts.

2. **P50 Latency <100ms**: Half of all requests complete in under 100ms, which is excellent for a health check endpoint. This confirms the optimization (removing COUNT queries) was successful.

3. **P95 Latency <300ms**: 95% of requests complete in under 300ms, meaning only 5% of requests experience any delay. This is within acceptable production standards.

4. **Connection Leaks = 0**: The `Connection: close` header fix is working correctly, preventing CLOSE_WAIT connections from accumulating.
`─────────────────────────────────────────────────`

---

## 🐛 Troubleshooting

### **Issue: Terraform apply fails**

```bash
# Check AWS credentials
aws sts get-caller-identity

# Check if state bucket exists
aws s3 ls s3://catalytic-terraform-state

# If bucket doesn't exist, create it:
aws s3 mb s3://catalytic-terraform-state --region us-east-1

# Enable versioning
aws s3api put-bucket-versioning \
  --bucket catalytic-terraform-state \
  --versioning-configuration Status=Enabled
```

### **Issue: Can't connect to EC2 instance**

```bash
# Check security group allows SSH (port 22)
aws ec2 describe-security-groups --group-ids sg-xxxxxxxx

# Check instance is running
aws ec2 describe-instances --instance-ids i-xxxxxxxxx

# Try different user name
ssh -i "your-key.pem" ec2-user@ec2-xx-xx-xx-xx.compute-1.amazonaws.com
# Or:
ssh -i "your-key.pem" admin@ec2-xx-xx-xx-xx.compute-1.amazonaws.com
```

### **Issue: Load test fails with errors**

```bash
# Check ulimit
ulimit -n
# Should be 65536

# Check if enough memory
free -h
# Should have at least 2GB free

# Check server logs
tail -f server.log

# Try smaller user count first
locust -f tests/performance/simple_loadtest.py \
  --users 100 \
  --spawn-rate 20 \
  --run-time 60 \
  --host http://localhost:8000 \
  --headless
```

---

## 📊 What to Report Back

After successful deployment, gather these metrics:

```bash
# 1. Platform information
uname -a
ulimit -n

# 2. Load test results (copy from Locust output)
cat staging_1k_users_stats.csv | tail -1

# 3. Validation results
python validate_deployment.py --host http://localhost:8000

# 4. Server info
ps aux | grep start_server_optimized
netstat -an | grep ':8000' | wc -l
```

**Share:**
- Load test HTML report (staging_1k_users.html)
- Validation output (screenshot or text)
- Server resource usage during test

---

## ⏭️ Next Steps After Validation

### **If Load Tests Pass (>99% success):**

1. **Run 24-hour stability test:**
   ```bash
   locust -f tests/performance/simple_loadtest.py \
     --users 500 \
     --spawn-rate 50 \
     --run-time 86400 \
     --host http://localhost:8000 \
     --headless
   ```

2. **Configure monitoring:**
   - Set up Prometheus/Grafana
   - Configure alerts (Sentry, PagerDuty)
   - Enable log aggregation

3. **Prepare for production:**
   - Configure SSL certificates
   - Set up backup procedures
   - Document rollback plan
   - Schedule production deployment

### **If Load Tests Fail:**

1. **Gather diagnostic information:**
   ```bash
   # Server logs
   tail -100 server.log

   # System resources during test
   htop

   # Network connections
   netstat -an | grep ':8000'
   ```

2. **Common issues and fixes:**
   - High latency → Check database connection pooling
   - Timeouts → Increase uvicorn timeouts
   - Connection errors → Verify ulimit is set correctly
   - Memory issues → Increase instance size or add workers

3. **Contact support with:**
   - Load test results (HTML + CSV)
   - Server logs
   - System information (uname -a, free -h, df -h)

---

## 📞 Getting Help

### **Pre-Deployment Questions:**
- Review: [README_DEPLOYMENT.md](README_DEPLOYMENT.md)
- Review: [LOAD_TESTING_WINDOWS_LIMITATION_REPORT.md](LOAD_TESTING_WINDOWS_LIMITATION_REPORT.md)

### **During Deployment Issues:**
- Check: Troubleshooting section above
- Server logs: `tail -f server.log`
- Validation: `python validate_deployment.py`

### **Post-Deployment Questions:**
- Performance tuning: Adjust worker count, connection pools
- Scaling: Add more workers or instances
- Monitoring: Configure Prometheus, Grafana, Sentry

---

## ✅ Final Checklist

Before considering deployment complete:

```markdown
- [ ] Code pushed to GitHub (commit 358428cc)
- [ ] Linux server provisioned (EC2, EKS, or WSL2)
- [ ] ulimit -n 65536 configured
- [ ] Server deployed and running (4+ workers)
- [ ] Validation script passes (python validate_deployment.py)
- [ ] Baseline 100-user test passes (>99% success)
- [ ] Production 1K-user test passes (>99% success, <100ms P50)
- [ ] No connection leaks (0 CLOSE_WAIT)
- [ ] Results documented (HTML reports saved)
- [ ] 24-hour stability test scheduled (optional but recommended)
- [ ] Monitoring configured (for production)
- [ ] Backup procedures tested (for production)
```

---

**Document Version:** 1.0
**Last Updated:** October 22, 2025
**Estimated Completion Time:** 2-4 hours (depending on option chosen)
**Success Rate:** HIGH (code validated, scripts tested)

**Ready to Execute!** 🚀

Choose your deployment option and follow the step-by-step instructions above.