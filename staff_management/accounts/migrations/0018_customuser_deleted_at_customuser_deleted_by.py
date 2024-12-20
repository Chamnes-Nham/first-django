# Generated by Django 5.1.3 on 2024-11-29 03:22

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0017_alter_customuser_options_alter_customuser_managers'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='deleted_at',
            field=models.DateTimeField(blank=True, help_text='Time when user was deleted.', null=True),
        ),
        migrations.AddField(
            model_name='customuser',
            name='deleted_by',
            field=models.ForeignKey(blank=True, help_text='Who deleted this record', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='deleted_user', to=settings.AUTH_USER_MODEL),
        ),
    ]
