# Security Policy

AccessGov is an educational portfolio project and is not intended to protect or process production identity data.

## Reporting a vulnerability

If you discover a security issue, please avoid opening a public issue containing exploitation details. Contact the repository owner privately through the contact information available on their GitHub profile.

## Demo-data policy

All data committed to this repository must be synthetic. Never commit:

- employee exports
- production identity inventories
- access tokens or API keys
- real passwords
- real entitlement reports
- internal application names if confidential
- company-specific access review evidence

## Production note

The demo API intentionally has no authentication so the repository can be tested locally without external dependencies. This is not suitable for production use.
