# Gotcha #8

**8. Not every log has a numeric port column.**
Check Point names the service (`http`, `FW1_ica_services`) and has no port
field at all, so `R2002` (distinct destination ports) can never fire on it.
`R2003` counts distinct *services* for the same signal. When adding rules,
check whether the field you depend on actually exists across log sources.
