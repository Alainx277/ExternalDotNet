# ExternalDotNet
A C# class library for remote process manipulation. Work in progress.
## Usage
### Attaching to a process
#### With the process id
```CSharp
try
{
	External ex = new External(1234 /* Process id */);
	ex.OpenProcess(Native.ProcessAccessFlags.All /* Access flags */);
	// Additional code
}
catch (ProcessOpenException e)
{
	// Couldn't open process
}
```
#### With the process name
```CSharp
try
{
	External ex = new External("test.exe");
	ex.OpenProcess(Native.ProcessAccessFlags.All /* Access flags */);
	// Additional code
}
catch (ArgumentException e)
{
	// test.exe doesn't exist
}
catch (ProcessOpenException e)
{
	// Couldn't open process
}
```

### Memory Modification
```CSharp
// Write memory
external.Write<int>((IntPtr)0xDEADBEEF, 1337);

// Allocate memory
IntPtr allocatedPtr = external.Allocate((IntPtr) 0xDEADBEEF, 2048);
```

### Data extraction
```CSharp
// Read memory
int data = external.Read<int>((IntPtr)0xDEADBEEF);

// Check for module
bool exists = external.HasModule("test");

// Get module exports
Dictionary<string, IntPtr> exports = external.GetModuleExports("test");
```

### Execution
```CSharp
// Create thread
IntPtr handle = external.CreateThread((IntPtr) 0xDEADBEEF);

// Execute bytecode
IntPtr handle = external.Execute(new byte[]{ 123, 123, 123});

// Execute bytecode and wait for thread exit
IntPtr returnValue = await external.ExecuteAndWait(new byte[]{ 123, 123, 123}, true /* Cleanup memory? */);

// Call remote function and wait for thread exit
IntPtr returnValue = await external.ExecuteAndWait((IntPtr) 0xDEADBEEF, CallingConvention.Cdecl, (IntPtr)123, (IntPtr)123);
```
