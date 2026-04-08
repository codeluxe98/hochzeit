"""initial schema

Revision ID: 20260408_01
Revises:
Create Date: 2026-04-08
"""
from alembic import op
import sqlalchemy as sa


revision = '20260408_01'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('users',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('email', sa.String(255), nullable=False, unique=True),
        sa.Column('username', sa.String(100), nullable=False, unique=True),
        sa.Column('full_name', sa.String(255), nullable=False),
        sa.Column('password_hash', sa.String(255), nullable=False),
        sa.Column('role', sa.String(20), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('is_mfa_enabled', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
    )
    op.create_table('auth_sessions', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id')),
        sa.Column('refresh_token_hash', sa.String(255)), sa.Column('user_agent', sa.String(512)), sa.Column('ip_address', sa.String(64)), sa.Column('expires_at', sa.DateTime()), sa.Column('created_at', sa.DateTime()))
    op.create_table('webauthn_credentials', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id')), sa.Column('credential_id', sa.String(512), unique=True), sa.Column('public_key', sa.Text()), sa.Column('sign_count', sa.Integer()), sa.Column('transports', sa.Text()), sa.Column('created_at', sa.DateTime()))
    op.create_table('two_factor_settings', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), unique=True), sa.Column('secret_encrypted', sa.Text()), sa.Column('recovery_codes_encrypted', sa.Text()), sa.Column('enabled', sa.Boolean()), sa.Column('created_at', sa.DateTime()))
    op.create_table('server_groups', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('name', sa.String(120), unique=True), sa.Column('description', sa.String(512)), sa.Column('created_at', sa.DateTime()))
    op.create_table('servers', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('name', sa.String(120), unique=True), sa.Column('host', sa.String(255)), sa.Column('host_type', sa.String(40)), sa.Column('location', sa.String(40)), sa.Column('status', sa.String(20)), sa.Column('notes', sa.String(1000)), sa.Column('created_at', sa.DateTime()), sa.Column('updated_at', sa.DateTime()))
    op.create_table('server_group_items', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('server_id', sa.Integer(), sa.ForeignKey('servers.id')), sa.Column('group_id', sa.Integer(), sa.ForeignKey('server_groups.id')), sa.Column('created_at', sa.DateTime()))
    op.create_table('integrations', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('key', sa.String(80), unique=True), sa.Column('name', sa.String(120)), sa.Column('enabled', sa.Boolean()), sa.Column('config_json', sa.Text()), sa.Column('created_at', sa.DateTime()))
    op.create_table('actions', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('server_id', sa.Integer(), sa.ForeignKey('servers.id')), sa.Column('requested_by_user_id', sa.Integer(), sa.ForeignKey('users.id')), sa.Column('action_type', sa.String(80)), sa.Column('payload_json', sa.Text()), sa.Column('status', sa.String(30)), sa.Column('created_at', sa.DateTime()), sa.Column('finished_at', sa.DateTime(), nullable=True))
    op.create_table('audit_logs', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=True), sa.Column('action', sa.String(120)), sa.Column('target_type', sa.String(80)), sa.Column('target_id', sa.String(120)), sa.Column('status', sa.String(40)), sa.Column('details', sa.Text()), sa.Column('created_at', sa.DateTime()))
    op.create_table('terminal_sessions', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('server_id', sa.Integer(), sa.ForeignKey('servers.id')), sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id')), sa.Column('status', sa.String(30)), sa.Column('websocket_channel', sa.String(160)), sa.Column('created_at', sa.DateTime()))
    op.create_table('metrics_snapshots', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('server_id', sa.Integer(), sa.ForeignKey('servers.id')), sa.Column('cpu_percent', sa.Float()), sa.Column('ram_percent', sa.Float()), sa.Column('storage_percent', sa.Float()), sa.Column('network_in_kbps', sa.Float()), sa.Column('network_out_kbps', sa.Float()), sa.Column('timestamp', sa.DateTime()))


def downgrade() -> None:
    for table in ['metrics_snapshots', 'terminal_sessions', 'audit_logs', 'actions', 'integrations', 'server_group_items', 'servers', 'server_groups', 'two_factor_settings', 'webauthn_credentials', 'auth_sessions', 'users']:
        op.drop_table(table)
