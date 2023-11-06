# Generated by Django 4.2.6 on 2023-11-04 11:28

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('A_Vastralaya_home', '0003_alter_orders_order_date'),
    ]

    operations = [
        migrations.AddField(
            model_name='products',
            name='p_size',
            field=models.CharField(default=0, max_length=10),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='orders',
            name='order_date',
            field=models.DateTimeField(default=datetime.datetime(2023, 11, 4, 11, 27, 59, 673813, tzinfo=datetime.timezone.utc)),
        ),
    ]