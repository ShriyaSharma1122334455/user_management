"""initial migration

Revision ID: 25d814bc83ed
Revises: 
Create Date: 2024-04-21 09:51:44.977108

"""
import os
import warnings
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import text
import uuid
from app.utils.security import hash_password
from app.models.user_model import UserRole

warnings.warn("Test data functions should be moved to separate seed files", UserWarning)

# revision identifiers, used by Alembic.
revision: str = '25d814bc83ed'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('users',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('nickname', sa.String(length=50), nullable=False, 
                comment='Unique display name'),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('first_name', sa.String(length=100), nullable=True),
        sa.Column('last_name', sa.String(length=100), nullable=True),
        sa.Column('bio', sa.Text(), nullable=True),
        sa.Column('profile_picture_url', sa.String(length=255), nullable=True),
        sa.Column('linkedin_profile_url', sa.String(length=255), nullable=True),
        sa.Column('github_profile_url', sa.String(length=255), nullable=True),
        sa.Column('role', sa.Enum('ANONYMOUS', 'AUTHENTICATED', 'MANAGER', 'ADMIN', 
                name='UserRole', create_constraint=True), nullable=False),
        sa.Column('is_professional', sa.Boolean(), nullable=True, 
                comment='Professional account status'),
        sa.Column('professional_status_updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('failed_login_attempts', sa.Integer(), server_default='0'),
        sa.Column('is_locked', sa.Boolean(), server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), 
                server_default=sa.text('now() AT TIME ZONE \'UTC\'')),
        sa.Column('updated_at', sa.DateTime(timezone=True), 
                server_default=sa.text('now() AT TIME ZONE \'UTC\'')),
        sa.Column('verification_token', sa.String(), nullable=True),
        sa.Column('email_verified', sa.Boolean(), server_default='false'),
        sa.Column('hashed_password', sa.String(length=1024), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), server_default='false'),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.CheckConstraint('length(nickname) >= 3', name='ck_nickname_length')
    )
    
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_nickname'), 'users', ['nickname'], unique=True)
    op.create_index('idx_users_role_status', 'users', ['role', 'is_professional'])
    
    op.create_check_constraint(
        'ck_user_email_format',
        'users',
        "email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$'"
    )


def downgrade() -> None:
    op.drop_constraint('ck_user_email_format', 'users', type_='check')
    op.drop_constraint('ck_nickname_length', 'users', type_='check')
    op.drop_index('idx_users_role_status', table_name='users')
    op.drop_index(op.f('ix_users_nickname'), table_name='users')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')
    sa.Enum(name='UserRole').drop(op.get_bind())