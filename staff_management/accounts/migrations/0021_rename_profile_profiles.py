# Generated by Django 5.0.9 on 2024-12-13 01:37

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0020_profile'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='Profile',
            new_name='Profiles',
        ),
    ]
