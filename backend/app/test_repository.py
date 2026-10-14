from app.database.repository import (
    get_customers,
    get_customer_vendors,
    get_cves,
    get_alerts
)

print("Customers:")
print(get_customers())

print("\nVendors:")
print(get_customer_vendors())

print("\nCVEs:")
print(get_cves()[:5])

print("\nAlerts:")
print(get_alerts())