# Generated by Django 5.1.3 on 2024-11-22 07:51

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0004_rolepermission'),
    ]

    operations = [
        migrations.RenameField(
            model_name='rolepermission',
            old_name='allowed_fields',
            new_name='fields_allowed',
        ),
        migrations.RemoveField(
            model_name='rolepermission',
            name='full_table_access',
        ),
    ]
