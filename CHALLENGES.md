# Scaling Challenges at 100k+ Domains

## Performance Bottlenecks
If you have a large amount of domain names it may have a large amount of write queries.
Server can have a lot of load as it checks a large amount of domains to download js files.
Regex pattern may be mismatched


###  Database Limitations
- **SQLite contention** with concurrent writes from multiple workers
- **No built-in replication** for high availability

### Database Scaling
- **PostgreSQL migration** with proper connection pooling
- **Read replicas** for analytics and reporting
- **Sharding** by domain hash or geographic region

### Processing Architecture
- **Domain sharding** across multiple worker instances
- **Message queue** (Redis) for job distribution
- **Kubernetes deployment** with auto-scaling

### Storage Optimization
- **S3/GCS integration** for blob storage

## Cost Optimization
- **CDN caching** for frequently accessed JS files