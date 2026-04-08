from pydantic import BaseModel


class DashboardOverview(BaseModel):
    total_servers: int
    online_servers: int
    offline_servers: int
    avg_cpu: float
    avg_ram: float
    recent_actions: int
    warnings: int
