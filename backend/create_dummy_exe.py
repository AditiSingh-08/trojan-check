# create_dummy_exe.py
with open("dummy.exe", "wb") as f:
    # Write the "MZ" header which identifies Windows executables.
    f.write(b"MZ")
    # Add some padding bytes (e.g., 100 NOP instructions or zeros).
    f.write(b"\x90" * 100)
