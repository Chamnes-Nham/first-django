# Generated by Django 5.1.3 on 2024-11-28 01:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0008_remove_rolepermission_user_userpermission'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='customuser',
            options={},
        ),
        migrations.AlterModelManagers(
            name='customuser',
            managers=[
            ],
        ),
        migrations.AddField(
            model_name='auditlog',
            name='deleted_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='auditlog',
            name='restored_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='auditlog',
            name='transaction_id',
            field=models.UUIDField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='customuser',
            name='deleted_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='customuser',
            name='restored_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='customuser',
            name='transaction_id',
            field=models.UUIDField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='rolepermission',
            name='deleted_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='rolepermission',
            name='restored_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='rolepermission',
            name='transaction_id',
            field=models.UUIDField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='userpermission',
            name='deleted_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='userpermission',
            name='restored_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='userpermission',
            name='transaction_id',
            field=models.UUIDField(blank=True, null=True),
        ),
    ]
