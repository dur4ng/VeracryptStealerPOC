# VeraCrypt Stealer

## Api monitor v2 analysis

```
# Time of Day Thread Module API Return Value Error Duration
16707 12:56:16.945 PM 2 VeraCrypt.exe WideCharToMultiByte ( CP_UTF8, 0, "TESTMODEdrive", -1, 0x00007ff74334c744, 129, NULL, NULL ) 14 0.0000014
```

The app passes the password in plaintext via WideCharToMultiByte. Therefore, it is possible to steal the password by hooking this function.

## Stealer
This module hooks WideCharToMultiByte using detours, capturing the Veracrypt password when the user decrypts the disk. The captured password is then saved to C:\Windows\Temp\data.txt.

## Loader
The loader functions as a shellcode injector. It is expected to convert the stealer DLL to shellcode using the sRDI project.
Link to sRDI proyect: https://github.com/monoxgas/sRDI

```
python3 .\sRDI\Python\ConvertToShellcode.py .\VeraCryptPasswordStealer.dll -f Go
```