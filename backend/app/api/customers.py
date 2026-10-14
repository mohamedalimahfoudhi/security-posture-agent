from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, constr
from app.auth.deps import get_current_user, require_roles
from app.database.repository import get_customers, get_all_customers, create_customer, update_customer, delete_customer

router = APIRouter(
    prefix="/api/customers",
    tags=["Customers"]
)

class CustomerCreate(BaseModel):
    name: constr(strip_whitespace=True, min_length=1, max_length=100)
    industry: str = None

class CustomerUpdate(BaseModel):
    name: constr(strip_whitespace=True, min_length=1, max_length=100)
    industry: str = None

@router.get("/")
def read_customers(current_user: dict = Depends(get_current_user)):
    customers = [customer for customer in get_customers() if customer[0] == current_user["customer_id"]]

    return [
        {
            "id": customer[0],
            "name": customer[1]
        }
        for customer in customers
    ]

@router.get("/all")
def read_all_customers(current_user: dict = Depends(require_roles("Admin"))):
    """Admin-only: return all customers for customer-switching UI."""
    return get_all_customers()

@router.post("/", status_code=status.HTTP_201_CREATED)
def create_customer_endpoint(customer: CustomerCreate, current_user: dict = Depends(require_roles("Admin"))):
    """Admin-only: Create a new customer."""
    try:
        return create_customer(customer.name, customer.industry)
    except Exception as e:
        if "unique constraint" in str(e).lower() or "duplicate key" in str(e).lower():
            raise HTTPException(status_code=400, detail="Customer with this name already exists")
        raise HTTPException(status_code=500, detail=f"Failed to create customer: {e}")

@router.patch("/{customer_id}")
def update_customer_endpoint(customer_id: int, customer: CustomerUpdate, current_user: dict = Depends(require_roles("Admin"))):
    """Admin-only: Update a customer."""
    try:
        updated = update_customer(customer_id, customer.name, customer.industry)
        if not updated:
            raise HTTPException(status_code=404, detail="Customer not found")
        return updated
    except Exception as e:
        if "unique constraint" in str(e).lower() or "duplicate key" in str(e).lower():
            raise HTTPException(status_code=400, detail="Customer with this name already exists")
        raise HTTPException(status_code=500, detail=f"Failed to update customer: {e}")

@router.delete("/{customer_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_customer_endpoint(customer_id: int, current_user: dict = Depends(require_roles("Admin"))):
    """Admin-only: Safely delete a customer and all its tenant-owned dependencies."""
    try:
        deleted = delete_customer(customer_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Customer not found")
        return None
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to safely delete customer: {e}")
