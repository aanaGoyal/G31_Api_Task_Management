# Generated by Django 5.1.7 on 2025-04-10 07:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('DashboardApp', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='task',
            name='progress',
            field=models.PositiveIntegerField(default=0),
        ),
    ]
