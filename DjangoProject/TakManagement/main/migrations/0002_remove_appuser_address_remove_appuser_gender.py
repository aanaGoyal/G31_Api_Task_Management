# Generated by Django 5.2 on 2025-04-13 09:25

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='appuser',
            name='address',
        ),
        migrations.RemoveField(
            model_name='appuser',
            name='gender',
        ),
    ]
