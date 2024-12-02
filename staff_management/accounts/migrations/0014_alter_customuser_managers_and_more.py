# Generated by Django 5.1.3 on 2024-11-28 09:30

import django.contrib.auth.models
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0013_alter_customuser_managers_customuser_deleted_at_and_more'),
    ]

    operations = [
        migrations.AlterModelManagers(
            name='customuser',
            managers=[
                ('objects', django.contrib.auth.models.UserManager()),
            ],
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='deleted_at',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='is_deleted',
        ),
    ]
