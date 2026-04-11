# UI Refactor Safety Checklist

Use this before merging any change that touches UI boot code, especially:
- server/app/templates/index.html
- server/app/templates/fleet-phase3-*.js

## Mandatory checks

1. Run frontend tests

```bash
npm run test:frontend
```

2. If index.html changed, verify file tail

```bash
tail -n 20 server/app/templates/index.html
```

Confirm the file still ends with:
- </script>
- </body>
- </html>

3. Keep commits narrowly scoped
- do not mix unrelated features into the same index.html edit
- do not batch multiple risky UI changes into one commit

4. Manual browser sanity check after rebuild
- login works
- settings menu opens
- Dashboard tab opens
- Hosts tab opens
- Admin tab opens (for admin user)

5. If host metadata or filters changed
- host metadata save works
- host list still renders
- Host Inventory still renders

6. If access-control/scoping changed
- regular user only sees allowed hosts
- inventory/report views do not leak hidden hosts

## Strong recommendation
- prefer changes in small JS modules over direct edits to index.html
- if index.html must change, keep it shell-level only when possible
