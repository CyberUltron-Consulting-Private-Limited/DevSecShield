# AWS lab teardown — pending (credentials rejected since the 10:20 UTC Nov 5 restart)

When access returns (or for the owner to do by hand; everything is tagged zs-lab=sandbox, ap-south-1):
1. `cd round5/lab && bash run/aws_lab.sh destroy` — tofu plan -destroy -out, review, apply the saved plan.
   Local tfstate: round5/lab/terraform (keep until destroy succeeds).
2. Created outside tofu by U1 (Nov 5, 08:50–09:45): CloudFormation stack `u1-zs-cbom-reader` (creates IAM role
   `u1-ZeroShieldCBOMReader`) — delete the stack before/after tofu destroy (tofu does not know it).
   RDS roles u1_cbom (Postgres zscbom-pg-weak) and 'u1_cbom'@'%' (MySQL) go with the RDS instances.
3. Leftover check: Resource Groups tag query zs-lab=sandbox in ap-south-1 and us-east-1 (CloudTrail bucket?), plus
   `aws cloudformation list-stacks`, IAM roles with prefix zscbom/u1-.
4. Then delete locally: secrets/aws-session.env, adcs-reader.json, r5-canaries.json, r5-pool-token, lab-admin.json,
   lab/seed/out credentials, apply logs with canaries, tfstate.
Note: U1 saved a never-scan exclusion 10.0.0.0/7 in lab team 1 for ~1 minute (Nov 5 09:29:40–09:30:43 UTC).
