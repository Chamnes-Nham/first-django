# Generated by Django 5.1.3 on 2024-11-28 07:29

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0011_remove_auditlog_deleted_at_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='customuser',
            name='deleted_at',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='restored_at',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='transaction_id',
        ),
    ]
