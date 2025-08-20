# Scaling Challenges at 100k+ Domains

## Performance Bottlenecks

### 1. Database Limitations
- **SQLite contention** with concurrent writes from multiple workers
- **No built-in replication** for high availability
- **Limited connection pooling** capabilities

### 2. Network & I/O Constraints
- **DNS resolution overhead** for massive domain lists
- **Bandwidth saturation** from simultaneous HTTP requests
- **Rate limiting** from target domains and CDNs

### 3. Storage Scaling
- **Local filesystem limits** for millions of JS blobs
- **No built-in compression** or deduplication at scale

## Scaling Levers

### 1. Database Scaling
- **PostgreSQL migration** with proper connection pooling
- **Read replicas** for analytics and reporting
- **Sharding** by domain hash or geographic region

### 2. Processing Architecture
- **Domain sharding** across multiple worker instances
- **Message queue** (Redis/RabbitMQ) for job distribution
- **Kubernetes deployment** with auto-scaling

### 3. Storage Optimization
- **S3/GCS integration** for blob storage with lifecycle policies
- **Content-addressable storage** with deduplication
- **Cold storage** archiving for historical JS files

## Cost Optimization
- **Spot instances** for processing workers
- **CDN caching** for frequently accessed JS files
- **Aggressive compression** and retention policies