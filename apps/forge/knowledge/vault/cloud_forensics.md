# Cloud Platform Forensics & Security

## AWS (Amazon Web Services)

### Key Services
| Service | Description | Forensics Value |
|---------|-------------|-----------------|
| CloudTrail | API logging | Who did what |
| CloudWatch | Monitoring | Performance logs |
| VPC Flow Logs | Network traffic | Network forensics |
| S3 | Object storage | Bucket analysis |
| IAM | Identity management | Access patterns |
| Lambda | Serverless | Function logs |
| GuardDuty | Threat detection | Alerts |
| Macie | Data classification | Sensitive data |

### AWS Artifacts
```
# CloudTrail
aws_cloudtrail_events

# CloudWatch Logs
/var/log/messages
/var/log/secure

# VPC Flow Logs
vpc_flow_logs

# S3 Access Logs
s3_access_logs

# Load Balancer Logs
elb_access_logs
```

### AWS Forensics Commands
```bash
# List CloudTrail events
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser

# Get S3 bucket policy
aws s3api get-bucket-policy --bucket <name>

# List IAM user activities
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=<user>

# Get VPC flow logs
aws ec2 describe-flow-logs

# GuardDuty findings
aws guardduty list-findings --detector-id <id>
```

### AWS Security Services
- **IAM**: Identity and Access Management
- **KMS**: Key Management Service
- **Secrets Manager**: Credential storage
- **Security Hub**: Centralized security
- **Config**: Resource tracking

## Azure

### Key Services
| Service | Description | Forensics Value |
|---------|-------------|-----------------|
| Azure Monitor | Logging | Comprehensive logs |
| Azure AD | Identity | Sign-in logs |
| Azure Sentinel | SIEM | Threat detection |
| Log Analytics | Log storage | Query logs |
| Storage Analytics | Storage logging | Access logs |
| Network Watcher | Network diagnostics | Flow logs |

### Azure Artifacts
```
# Sign-in logs
Azure AD Sign-in Logs

# Audit logs
Azure Audit Logs

# Resource logs
Azure Resource Manager

# Network logs
Network Security Group Flow Logs

# Storage logs
Storage Analytics
```

### Azure Forensics Commands
```powershell
# Get Azure AD sign-in logs
Get-AzureADAuditSignInLogs

# Get audit logs
Get-AzureADAuditDirectoryLogs

# List security alerts
Get-AzSecurityAlert

# Network watcher
Get-AzNetworkWatcherFlowLogStatus

# VM activity
Get-AzLog -ResourceGroupName <name>
```

## Google Cloud Platform (GCP)

### Key Services
| Service | Description | Forensics Value |
|---------|-------------|-----------------|
| Cloud Logging | Centralized logging | All logs |
| Cloud Audit Logs | Admin activity | Who did what |
| VPC Flow Logs | Network traffic | Network forensics |
| Cloud Storage | Object storage | Access logs |
| Chronicle | SIEM | Threat detection |

### GCP Artifacts
```
# Admin activity logs
cloudaudit.googleapis.com/activity

# Data access logs
cloudaudit.googleapis.com/data_access

# System events
cloudaudit.googleapis.com/system_event

# Network flows
VPC Flow Logs
```

### GCP Forensics Commands
```bash
# List audit logs
gcloud logging read "logName:cloudaudit.googleapis.com/activity"

# Get VPC flow logs
gcloud compute firewall-logs list

# List buckets
gsutil ls

# Get bucket metadata
gsutil stat gs://bucket/name
```

## Cloud Forensics Checklist

### Phase 1: Collection
- [ ] Identify cloud provider
- [ ] Collect audit logs
- [ ] Collect network logs
- [ ] Collect storage logs
- [ ] Identify affected resources

### Phase 2: Analysis
- [ ] Timeline creation
- [ ] Identify attacker TTPs
- [ ] Determine blast radius
- [ ] Identify persistence mechanisms

### Phase 3: Containment
- [ ] Isolate compromised resources
- [ ] Revoke access credentials
- [ ] Block malicious IPs/domains

### Phase 4: Recovery
- [ ] Rebuild clean instances
- [ ] Restore from backups
- [ ] Verify integrity

## Container Forensics (Docker/Kubernetes)

### Docker Artifacts
```
/var/lib/docker/containers/ - Container logs
/var/lib/docker/ - Docker storage
/etc/docker/ - Docker config
```

### Docker Forensics Commands
```bash
# List containers
docker ps -a

# Container inspect
docker inspect <container_id>

# Container logs
docker logs <container_id>

# Container file system
docker export <container_id> > container.tar

# Running processes
docker top <container_id>
```

### Kubernetes Artifacts
```
/var/log/pods/ - Pod logs
/etc/kubernetes/ - K8s config
~/.kube/config - Kubeconfig
```

### K8s Forensics Commands
```bash
# Get pod events
kubectl get events

# Pod logs
kubectl logs <pod>

# Describe resource
kubectl describe pod <pod>

# API server audit logs
/var/log/kubernetes/kube-apiserver/
```

## Multi-Cloud Forensics

### Tools
- **MITRE ATT&CK Cloud Matrix**: https://attack.mitre.org/matrices/enterprise/cloud/
- **GCP Forensics**: google-cloud-forensics
- **Azure Forensics**: AzureAD powershell modules

### Key Evidence Sources
| Source | AWS | Azure | GCP |
|--------|-----|-------|-----|
| API Calls | CloudTrail | Audit Logs | Cloud Logging |
| Network | VPC Flow | NSG Flow | VPC Flow |
| Storage | S3 Logs | Storage Analytics | Cloud Storage |
| Auth | IAM | Azure AD | IAM |
| Config | Config | Resource Manager | Config |
