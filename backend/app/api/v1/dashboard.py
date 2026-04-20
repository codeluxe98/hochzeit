from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from app.core.deps import get_current_user
from app.db.session import get_session
from app.models.operations import Action, MetricsSnapshot
from app.models.server import Server
from app.models.user import User
from app.schemas.dashboard import DashboardOverview

router = APIRouter(prefix='/dashboard', tags=['dashboard'])


@router.get('/overview', response_model=DashboardOverview)
def overview(
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    servers = session.exec(select(Server)).all()
    metrics = session.exec(select(MetricsSnapshot)).all()
    recent_actions = session.exec(select(Action)).all()

    avg_cpu = sum(m.cpu_percent for m in metrics) / len(metrics) if metrics else 0
    avg_ram = sum(m.ram_percent for m in metrics) / len(metrics) if metrics else 0
    online = len([s for s in servers if s.status == 'online'])
    offline = len(servers) - online

    return DashboardOverview(
        total_servers=len(servers),
        online_servers=online,
        offline_servers=offline,
        avg_cpu=round(avg_cpu, 1),
        avg_ram=round(avg_ram, 1),
        recent_actions=len(recent_actions),
        warnings=offline,
    )
