# Current Architecture & Bottlenecks  
The system today runs on a single AWS EC2 t3a.xlarge instance (4 vCPU, 16 GB RAM) hosting ~12 containers, and it OOM’s with just a handful of concurrent users.  This clearly hits both compute and memory limits.  At ~100 users, CPU and RAM are saturated, and the machine can’t autoscale on its own.  With a single node there is no horizontal scaling or fault‑tolerance.  In short, the bottleneck is mostly architectural (single-server capacity and design), though code inefficiencies or memory leaks likely amplify the problem.  To serve **100K requests/sec** we must **horizontally scale** (many nodes or containers) and massively improve throughput.  Immediate fixes (e.g. increasing instance size) can only get us so far; truly hitting 100K RPS requires a distributed, load‑balanced design. 

# Scaling Approaches & Best Practices  
To handle very high throughput, best practice is a *distributed* architecture with load balancing, autoscaling, and decoupling of components.  For example, AWS’s own guidance and case studies for 100K+ RPS recommend:  

- **Load balancing & sharding.**  Use multiple load balancers (ALB/NLB) with DNS‐level sharding (e.g. Route 53 weighted DNS) so traffic is split across many LB instances【39†L98-L106】【39†L138-L147】.  AWS suggests sharding the load balancer itself to spread 100K+ RPS across 2–3 ALBs, each pre-provisioned (reserved LCUs) to avoid cold‑start limits【13†L249-L258】【39†L98-L106】.  In practice you configure 3+ ALBs and use Route 53 to split incoming traffic.  Each ALB can then front a pool of application instances.  

- **Autoscaling and provisioning.**  Set up auto-scaling groups for your application servers or containers so you can add instances quickly.  However, as one case study found, **autoscaling alone may not catch a sudden 100× spike** in time【13†L158-L162】.  Adjoe (a sample tech blog) noted that for a planned 100K RPS event they *couldn’t* rely on reactive scaling and had to proactively provision all needed capacity days in advance【13†L158-L162】.  This means: identify peak demand early, and pre-scale (with on‑demand instances) to ensure resources are ready. Once traffic hits, the elastic load balancers will add more nodes behind the scenes, but only up to the prepared capacity.  

- **Caching & CDN.**  Introduce caching everywhere.  Use an edge CDN (e.g. Amazon CloudFront) for static assets and even API responses where possible, so user requests are served from cache rather than hitting your servers or databases.  Also use in‑memory caching (AWS ElastiCache Redis/Memcached) for hot data.  AWS notes that a single Redis/Memcached node can handle *hundreds of thousands to over a million requests per second* with sub-millisecond latency【22†L147-L156】.  This dramatically offloads databases: “in-memory caching is one of the most effective strategies to improve performance and reduce database costs”【22†L51-L59】【22†L147-L156】.  For example, in a high-load test, one team removed a hot DynamoDB config read by pushing it into ElastiCache, which eliminated a “hot partition” and sped up responses【11†L369-L378】.  

- **Asynchronous decoupling.**  Use queues (SNS/SQS, Amazon MQ, Kafka, etc.) to decouple request handling.  Instead of handling everything synchronously in one request, push tasks into a message queue and process them with worker pools.  In our example above, the team hit AWS rate limits on SNS/SQS when they went unbatched; by switching to batched SendMessageBatch calls they cut API calls by ~10× for the same payload【13†L301-L308】.  In general, batching and compression in message buses can drastically reduce overhead【13†L301-L308】. 

- **DynamoDB (or similar) for scale.**  For very high read/write rates, a fully-managed NoSQL like DynamoDB can scale near-infinitely (millions of RPS) without sharding.  It auto-splits partitions under heavy load.  AWS recently cut DynamoDB on-demand pricing by 50%【28†L75-L84】, making it even more cost-effective for unpredictable spikes.  In practice, DynamoDB (on-demand mode) can automatically accommodate sudden jumps (and supports “warm up” to pre-provision capacity)【28†L127-L136】. However, watch out for **hot keys**: a single key read repeatedly can throttle one partition (as happened in Adjoe’s test【11†L369-L378】).  The remedy is multi-partition keys or caching hot entries.  

# Compute & Container Options (Cost Focus)  
There are several AWS compute patterns to compare, each with trade-offs:  

- **EC2 instances (ECS/EKS).**  Running containers on EC2 (ECS or EKS on EC2) gives you full control.  You can use spot instances to slash costs (up to ~90% cheaper than on-demand【20†L367-L374】) and reserved instances or Savings Plans for base load (up to ~72% off【26†L232-L240】).  For example, the case study above normally ran ~90–100% of workloads on spot instances【13†L264-L272】. In ECS you pay only for the EC2 instances (no extra fee), whereas EKS adds a $0.10/hr control-plane charge per cluster【17†L574-L581】.  So **ECS (EC2 mode)** is often cheapest upfront.  However, ECS still requires you to manage node scaling.  When demand rises, ECS will spin up new t3 (or whatever) nodes in your cluster, incurring extra cost for those nodes (the user correctly worried it would “3× cost if scale by 3 instances”).  That is true: adding 3 more xlarge nodes would triple the EC2 bill (unless they are spot/reserved).  But with spots you can minimize that.  

- **AWS Fargate.**  Fargate (on-demand containers) removes server management, auto-scales pods, and charges per vCPU-second.  It’s easy but **more expensive at scale** (AWS’s docs note it shifts costs to pay-per-cpu; it integrates with ECS or EKS)【17†L574-L581】.  Fargate Spot can save ~70% on top of Fargate costs【24†L1-L4】.  Fargate is best for bursty or unpredictable loads where you want hands-off scaling.  But at constant 100K RPS, running long-lived Fargate tasks might cost significantly more than EC2 with spots/reservations.  

- **AWS EKS (Kubernetes).**  EKS lets you use Kubernetes on AWS.  It has a management fee ($0.10/hr/cluster【17†L574-L581】) and generally higher operational overhead.  It offers advanced autoscaling (Karpenter or Cluster Autoscaler) and portability (multi-cloud)【17†L574-L581】【18†L578-L584】.  If you already use K8s, EKS can work, but for a cost-constrained new project ECS is usually simpler and cheaper.  

- **Serverless (Lambda, etc.).**  AWS Lambda scales effortlessly up to large concurrency (subject to account limits, which can be raised).  However, Lambda pricing is per-request and per-execution time.  At 100K RPS sustained, Lambda can become very costly (though the price per million requests is low ~$0.20/million【23†L5-L9】, the compute time cost can add up).  There are also concurrency limits by default (1,000 concurrent executions/account per region【23†L1-L4】).  Thus, Lambda is generally *not* ideal for ultra-high sustained throughput.  It may still be useful for auxiliary tasks (file processing, async jobs), but the main API workload likely should run on long-lived containers or servers for cost efficiency.  

In summary, **for cost-minimising** at very high scale, the common advice is to run containers on EC2 (ECS): reserve (or spot) enough instances, and use ECS Services and Target Groups behind ALBs.  Use spot instances or Graviton-based instances (e.g. T4g/C6g) for cheaper compute.  Run minimal on-demand or reserved for stability, and schedule the rest on spot.  Fargate simplifies ops but expect a higher hourly bill (unless you use Fargate Spot for some tasks).  EKS adds management cost and complexity, and is usually chosen for portability or K8s-specific features, not cost.  

# Code‑Level Optimisations  
Alongside architecture, the application code must be efficient.  Key areas to optimize:

- **Concurrency & non-blocking I/O.**  Use an asynchronous or highly concurrent stack (e.g. Golang, Node.js async, Java with non-blocking IO) to handle many simultaneous requests.  Languages like Go tend to have lower overhead per request, which translates to lower CPU use (and cost) under high load【34†L58-L62】【34†L68-L76】.  Profile the code to eliminate bottlenecks: slow database queries, synchronous file or network calls, and excessive logging.  For example, if using Python or Node, ensure long-running tasks are moved to background workers so threads aren’t held up.  

- **Database/query tuning.**  Optimize all database access.  Add proper indexes, avoid N+1 query loops, and batch queries where possible.  If using relational DB (RDS), scale reads with replicas.  If using DynamoDB, design keys to avoid hot partitions (spread writes/reads evenly).  If a single config row is read 100K×/sec (as in the Adjoe test), move it to cache or duplicate it per partition【11†L369-L378】.  

- **Caching patterns.**  Implement cache-aside or write-through caches.  For example, read-through Redis cache for frequently-read data.  Cache entire API responses if they are identical for many users (e.g. use Varnish or CloudFront edge).  Remember to set TTLs appropriately so cache stays valid.  AWS recommends cache-aside patterns (fetch from DB if cache miss, then populate cache) for scalability【22†L51-L59】【22†L147-L156】.  

- **Asynchronous work.**  Any heavy computation or I/O (image processing, sending emails, video encoding) should be offloaded to asynchronous jobs.  Users get quick responses, and worker pools process jobs in the background.  This smooths out load and avoids tying up web servers.  

- **Compression & payloads.**  Use gzip or brotli for responses to reduce bandwidth.  Send compact data.  Smaller payloads save network I/O and LCU usage on ALBs.  Also enable keep-alive to reduce connection overhead.  

Every micro-optimization counts at 100K RPS.  Collect detailed metrics (CPU, memory, latency) on each component (e.g. using AWS X-Ray or CloudWatch).  Identify if code is CPU-bound (maybe the language/framework is too slow) or I/O-bound (maybe DB or external API is the issue).  Fix the hottest functions first.  

# Caching & Data Scaling  
Data stores often fail first under load.  Key strategies:

- **Read replicas and NoSQL.**  If using RDS (SQL), add multiple read replicas to spread the read load, and use a proxy or the “reader endpoint” to load-balance reads.  For writes, vertical scale to a larger instance (or use RDS Aurora, which can scale to high write rates).  If write throughput is extreme, consider a switch to DynamoDB (serverless) or a combination (e.g. write‑heavy data to Dynamo, relational to RDS).  

- **DynamoDB on-demand.**  As noted, on-demand DynamoDB now cost ≈50% less【28†L75-L84】 and auto-scales without limits.  It can easily handle millions of RPS if accessed properly.  Use on-demand mode for unpredictable peaks (it scales instantly, you pay per request)【28†L75-L84】.  If the access pattern is predictable, provisioned mode with auto-scaling can be cheaper, but managing limits is tricky.  

- **ElastiCache for hot data.**  Put ultra-hot data into Redis/Memcached.  For example, session data or configuration that every request hits should live in a shared cache.  That cuts database reads dramatically【11†L369-L378】.  A typical ElastiCache cluster (e.g. 3-node Redis cluster) can serve easily 100K/sec with sub-ms latency【22†L147-L156】.  

- **CloudFront & edge caching.**  Serve static content and API gateways through CloudFront.  API Gateway + Lambda (with caching) or direct ALB + CloudFront can offload much of the work.  This also reduces egress costs by using CDN caches closer to users.  

# Cost-Optimisation Techniques  
Since cost is critical, apply all financial best practices:

- **Spot and Reserved Instances.**  Run as many workloads as possible on Spot Instances (interruptible) – they can be up to **90% cheaper** than On-Demand【20†L367-L374】.  For baseline capacity and critical services, use Reserved Instances or Savings Plans (e.g. 1- or 3-year terms) – these can cut EC2/ECS costs **up to ~72%**【26†L232-L240】.  In practice, a mixed strategy is best: keep core instances reserved (so you pay very little for them) and overflow on spot.  

- **Right-sizing & instance selection.**  Choose instance types for price/performance.  For example, AWS Graviton (ARM) instances (t4g, m6g, c6g) often cost ~20–40% less per CPU than x86 equivalents with similar speed.  Burst‑able types (T3/T4g) save money if CPU use is not constant.  Use AWS Cost Explorer or Compute Optimizer to find under-utilized instances and shrink them.  

- **Avoid over-provisioning.**  Turn off/scale down services when idle.  Use auto-scaling schedules (e.g. smaller at night).  Do not run more instances or containers than needed.  For example, if 100K RPS is only during business hours, scale to 3× capacity at night to save money.  

- **Monitoring & early adjustments.**  Use CloudWatch alarms and AWS Budgets to catch runaway costs.  Track cost and usage daily.  Tools like AWS Compute Optimizer and Trusted Advisor will highlight underused resources or cheaper alternatives (e.g. a T4g instead of a T3).  

- **Architectural trade-offs.**  Sometimes a more complex solution can reduce cost.  For instance, using a managed service like DynamoDB or Kinesis might cost more per unit than a self-hosted database, but eliminate the need for a cluster of EC2 machines.  Always compare the fully‑loaded cost (infrastructure + operational effort).  The Bytebase analysis notes that **DynamoDB suits unpredictable loads**, while RDS is cheaper for steady loads if fully utilized【26†L233-L242】【26†L247-L252】.  

# Proposed Phased Plan  
A step-by-step migration helps balance quick wins and long-term scale:

1. **Phase 0 – Emergency Stabilisation (Days 1–2):**  
   - **Right‑size immediately**: Temporarily upgrade the EC2 instance class (e.g. to m6g.xlarge or c6g.xlarge) to gain headroom and prevent OOM.  Turn on swap as a quick fix.  This buys breathing room while other work proceeds.  
   - **Instrument & monitor**: Deploy comprehensive monitoring (CloudWatch, X-Ray) to pinpoint bottlenecks (CPU, memory, I/O).  Review logs for errors or garbage collection issues.  
   - **Remove obvious waste**: Disable debug logging, free unused assets, and offload any non-essential workloads.  

2. **Phase 1 – Code-Level Optimisations (Week 1):**  
   - **Profiling**: Use load testing (k6, JMeter) at gradually higher loads.  Profile the app to find hot methods, slow DB calls, or contention.  
   - **Concurrency fixes**: Refactor to async I/O, remove thread-blocking calls, optimize libraries.  For example, switch synchronous loops to bulk operations (SQL `WHERE IN`, batched inserts, etc.).  
   - **Caching implementation**: Add Redis/Memcached caching for frequent DB lookups.  Migrate any in-process session store or config to ElastiCache.  Set appropriate TTLs.  
   - **Queue integration**: Move long tasks to SNS/SQS or Kafka.  Ensure batched publishes to SNS and use SendMessageBatch for SQS【13†L301-L308】.  

3. **Phase 2 – Architect for Scale (Weeks 2–4):**  
   - **Container orchestration**: Containerize (if not already) and deploy on a multi-node cluster.  *Option A:* AWS ECS on EC2 with an Auto Scaling Group. *Option B:* EKS with Karpenter/Autoscaler. For cost minimisation, ECS is simpler: no extra cluster fee【17†L574-L581】 and deep AWS integration【18†L578-L584】.  
   - **Auto-scaling rules**: Set CPU/RPS-based scaling policies.  Test them: scale up gradually, then down to zero instances in idle (if possible).  Ensure scale-up is fast enough.  Consider pre-warming by setting a minimum number of nodes for peak times.  
   - **Load balancer setup**: Deploy 2–3 ALBs with Route 53 weighted records for sharding【39†L98-L106】.  Use ALB (or NLB if TCP) with health checks.  Reserve LCU capacity for anticipated load spikes【39†L138-L147】.  
   - **Database/Data layer**: If RDS is used, add read replicas and consider Aurora for auto-scaling.  If not done already, migrate hot data to DynamoDB (on-demand) or add a DynamoDB-backed service for high writes.  For DynamoDB tables, consider enabling **Auto Scaling** or using on-demand mode (now cheaper)【28†L75-L84】.  Also pre-warm important tables or use the new “warm-up” feature for planned traffic surges【28†L127-L136】.  
   - **Caching & CDN**: Place ElastiCache clusters in front of any remaining DB reads.  Set up a CloudFront distribution for any static content or even API Gateway front-ends.  

4. **Phase 3 – Testing and Iteration (Month 2):**  
   - **Load testing**: Execute realistic stress tests (as in the Super Bowl case study【13†L158-L162】).  Simulate 100K RPS gradually.  Identify new bottlenecks (e.g. network, NLB, quotas).  
   - **Optimize**: Based on tests, tune autoscaling thresholds, add more nodes if needed, or increase database capacity.  For instance, if DynamoDB throttles, add more WCU/RCU or enable on-demand (so AWS auto-partitions more).  If ALB shows latency, consider adding more shards or pre-reserving more LCU【39†L98-L106】【13†L249-L258】.  
   - **Cost tuning**: Review actual cost after scale.  Purchase additional Reserved Instances or Savings Plans for instances that ran in tests.  Replace on-demand instances with reserved where safe.  Check for idle resources and tear them down.  

5. **Phase 4 – Production Rollout & Continuous Optimisation:**  
   - **Gradual rollout**: Flip traffic from the old single instance to the new scalable architecture, monitoring user impact.  Keep the old instance on standby during the cutover in case a rollback is needed.  
   - **Automate**: Script the deployment (CloudFormation/Terraform, CI/CD) so you can replicate or tweak easily.  Implement routine cost-control scripts (e.g. shut down dev/test clusters on nights/weekends).  
   - **Monitoring & alerting**: Set alerts on latency, error rates, and spend.  Use CloudWatch billing alarms to know if costs spike unexpectedly.  

Throughout all phases, **always measure performance against cost**.  For example, if doubling instances only gives 1.3× throughput, find the bottleneck instead of blindly adding more servers.  The lesson from adjoe’s example was to “do more with what we have” by batching SQS calls【13†L301-L308】 rather than only asking AWS for higher quotas.  Similarly, use spot instances where possible【13†L264-L272】【20†L367-L374】, but have on-demand fallback for reliability (they did exactly that, accepting higher cost for guaranteed capacity【13†L278-L286】).

# Conclusion  
Achieving 100K users/sec at minimal cost requires **both architecture and code changes**.  You must go beyond a single-instance setup: introduce load balancers, auto-scaling clusters, caching layers and resilient data stores.  At the same time, trim any code inefficiency: profile hot paths, eliminate blocking, and use high-performance stacks where practical.  Always apply cost-optimization tactics: use spot instances (up to ~90% savings【20†L367-L374】), reserve for steady-state loads (up to ~72% off【26†L232-L240】), and adopt pay-per-use models (e.g. DynamoDB on-demand at 50% lower price【28†L75-L84】).  By phasing changes—stabilising, optimising code, then overhauling architecture—you can scale to 100K RPS in a controlled way that meets strict budget goals.  The key trade-off is stability vs. cost: some on-demand/on‑reservation spending will be needed for reliability, but careful planning (pre-warming, reserved capacity) and aggressive caching can keep the monthly spend within the \$500–\$1000 target while reaching production-level scale.  

**Sources:** AWS scalability and cost guidelines【13†L158-L162】【39†L98-L106】【22†L51-L59】【20†L367-L374】【17†L574-L581】【28†L75-L84】【26†L232-L240】【11†L369-L378】.  (Case study references: Adjoe blog, AWS blog posts.)