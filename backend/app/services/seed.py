from sqlmodel import Session, select

from app.core.security import get_password_hash
from app.models.operations import Integration, MetricsSnapshot
from app.models.server import Server
from app.models.user import User


def seed_initial_data(session: Session) -> None:
    if session.exec(select(User)).first():
        return

    admin = User(
        email='superadmin@homeops.local',
        username='superadmin',
        full_name='Super Admin',
        password_hash=get_password_hash('ChangeMe!1234'),
        role='superadmin',
        is_mfa_enabled=False,
    )
    session.add(admin)

    servers = [
        Server(name='rpi-home-1', host='192.168.1.21', host_type='rpi', location='home', status='online'),
        Server(name='rpi-home-2', host='192.168.1.22', host_type='rpi', location='home', status='online'),
        Server(name='hetzner-main', host='10.10.10.10', host_type='hetzner', location='hetzner', status='online'),
        Server(name='hetzner-exit', host='10.10.10.11', host_type='hetzner', location='hetzner', status='offline'),
    ]
    for server in servers:
        session.add(server)

    for key in ['solar', 'ddns', 'wireguard', 'portainer', 'prometheus']:
        session.add(Integration(key=key, name=key.capitalize(), enabled=False))

    session.commit()

    db_servers = session.exec(select(Server)).all()
    for i, server in enumerate(db_servers, start=1):
        session.add(
            MetricsSnapshot(
                server_id=server.id,
                cpu_percent=20 + i * 7,
                ram_percent=35 + i * 6,
                storage_percent=40 + i * 5,
                network_in_kbps=300 + i * 70,
                network_out_kbps=210 + i * 60,
            )
        )

    session.commit()
