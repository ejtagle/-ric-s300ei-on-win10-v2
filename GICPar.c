#include "ntddk.h"
#include "parallel.h"

typedef struct _DEVICE_EXTENSION {
	PDEVICE_OBJECT DeviceObject;
	ULONG NtDeviceNumber;
	
	// Parallel port driver
	PDEVICE_OBJECT PortDeviceObject;

	// Parallel port information
	PHYSICAL_ADDRESS                OriginalController;
	PUCHAR                          Controller;
	ULONG                           SpanOfController;
	PPARALLEL_TRY_ALLOCATE_ROUTINE  TryAllocatePort;    // nonblocking callback to allocate port
	PPARALLEL_FREE_ROUTINE          FreePort;           // callback to free port
	PPARALLEL_QUERY_WAITERS_ROUTINE QueryNumWaiters;    // callback to query number of waiters for port allocation
	PVOID                           PortContext;        // context for callbacks to ParPort device

	// Scanner access
	UCHAR                           LineReadMode;		// Line Read Mode
} DEVICE_EXTENSION, * PDEVICE_EXTENSION;

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath);
NTSTATUS GICParDispatchOpen(IN PDEVICE_OBJECT pDevObj, IN PIRP Irp);
NTSTATUS GICParDispatchClose(IN PDEVICE_OBJECT pDevObj, IN PIRP Irp);
NTSTATUS GICParDispatchRead(IN PDEVICE_OBJECT pDevObj, IN PIRP Irp);
NTSTATUS GICParDispatchWrite(IN PDEVICE_OBJECT pDevObj, IN PIRP Irp);
NTSTATUS GICParDispatchShutdown(IN PDEVICE_OBJECT pDevObj, IN PIRP Irp);
NTSTATUS GICParDispatchCleanup(IN PDEVICE_OBJECT pDevObj, IN PIRP Irp);
NTSTATUS GICParDispatchIoCtl(IN PDEVICE_OBJECT pDevObj, IN PIRP Irp);
VOID     GICParDriverUnload(IN PDRIVER_OBJECT  DriverObject);
static NTSTATUS GICParCreateDevice(IN PDRIVER_OBJECT pDriverObject, IN ULONG NtDeviceNumber);
static VOID GICParDeleteDevice(IN PDRIVER_OBJECT pDriverObject, IN ULONG NtDeviceNumber);
static NTSTATUS GICParGetPortInfoFromPortDevice(IN OUT  PDEVICE_EXTENSION pDevExt);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, GICParDispatchOpen) 
#pragma alloc_text(PAGE, GICParDispatchClose) 
#pragma alloc_text(PAGE, GICParDispatchRead) 
#pragma alloc_text(PAGE, GICParDispatchWrite)
#pragma alloc_text(PAGE, GICParDispatchCleanup)
#pragma alloc_text(PAGE, GICParDispatchShutdown)
#pragma alloc_text(PAGE, GICParDispatchIoCtl)
#pragma alloc_text(PAGE, GICParDriverUnload)

#pragma alloc_text(INIT, GICParCreateDevice)
#pragma alloc_text(PAGE, GICParDeleteDevice)
#pragma alloc_text(PAGE, GICParGetPortInfoFromPortDevice)

#endif

#define	GICPAR_NT_DEVICE_NAME		L"\\Device\\GICPar"
#define	GICPAR_NT_PORT_DEVICE_NAME	L"\\Device\\ParallelPort"
#define	GICPAR_WIN32_DEVICE_NAME	L"\\DosDevices\\GICPar"
#define	GICPAR_DOS_DEVICES			L"\\DosDevices\\"
#define	GICPAR_DRIVER_NAME			L"GICPar"

#define	GICPAR_MAX_NAME_LENGTH		50
#define GICPAR_MAX_PARPORTS			16
#define GICPAR_REGISTER_SPAN		3


PDEVICE_EXTENSION pDevExts[GICPAR_MAX_PARPORTS] = { NULL };

NTSTATUS
GICParDispatchOpen(
	IN PDEVICE_OBJECT pDevObj,
	IN PIRP Irp
)
{
	PAGED_CODE();

	PIO_STACK_LOCATION          irpStack;
	PDEVICE_EXTENSION pDevExt = pDevObj->DeviceExtension;

	if (!pDevExt) {
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	irpStack = IoGetCurrentIrpStackLocation(Irp);
	if (irpStack->MajorFunction == IRP_MJ_CREATE) {

		// Try to open the parallel port
		if (!pDevExt->TryAllocatePort(pDevExt->PortContext)) {

			// Unable to open it. Fail the opening
			Irp->IoStatus.Information = 0;
			Irp->IoStatus.Status = STATUS_ADAPTER_HARDWARE_ERROR;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return STATUS_ADAPTER_HARDWARE_ERROR;
		}
	}

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return  STATUS_SUCCESS;
}

NTSTATUS
GICParDispatchClose(
	IN PDEVICE_OBJECT pDevObj,
	IN PIRP Irp
)
{
	PAGED_CODE();

	PIO_STACK_LOCATION          irpStack;
	PDEVICE_EXTENSION pDevExt = pDevObj->DeviceExtension;

	if (!pDevExt) {
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	irpStack = IoGetCurrentIrpStackLocation(Irp);
	if (irpStack->MajorFunction == IRP_MJ_CLOSE) {

		// Close the parallel port
		pDevExt->FreePort(pDevExt->PortContext);
	}

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return  STATUS_SUCCESS;
}

NTSTATUS
GICParDispatchRead(
	IN PDEVICE_OBJECT pDevObj,
	IN PIRP Irp
)
{
	PAGED_CODE();

	PIO_STACK_LOCATION          irpStack;
	PDEVICE_EXTENSION pDevExt = pDevObj->DeviceExtension;
	NTSTATUS			Status = STATUS_SUCCESS;
	ULONG_PTR           Information = 0;


	if (!pDevExt) {
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	irpStack = IoGetCurrentIrpStackLocation(Irp);

	if (irpStack->MajorFunction == IRP_MJ_READ) {
		PUCHAR currentAddress = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

		if (!currentAddress || irpStack->Parameters.Read.Length == 0) {
			Irp->IoStatus.Information = 0;
			Irp->IoStatus.Status = STATUS_SUCCESS;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return STATUS_SUCCESS;
		}

		// Depending on Scanner read mode, do
		switch (pDevExt->LineReadMode) {
		case 1: {
			// SPP mode
			PUCHAR addr = (PUCHAR)(pDevExt->OriginalController.LowPart & 0xFFFF);
			ULONG count = irpStack->Parameters.Read.Length;
			Information = count;
			PUCHAR dst = currentAddress;

			WRITE_PORT_UCHAR(addr, 0xFF);

			UCHAR orgCtl = READ_PORT_UCHAR(addr + 2);
			do {
				WRITE_PORT_UCHAR(addr + 2, orgCtl | (0x2 | 0x8));
				UCHAR rd1 = READ_PORT_UCHAR(addr + 1);
				WRITE_PORT_UCHAR(addr + 2, orgCtl & (~0x8));
				UCHAR rd2 = READ_PORT_UCHAR(addr + 1);
				WRITE_PORT_UCHAR(addr + 2, orgCtl & (~0x2));
				*dst++ = (rd2 >> 4) | (rd1 & 0xF0);
			} while (--count);
			break;
		}
		case 2: {
			// PS2 mode
			PUCHAR addr = (PUCHAR)(pDevExt->OriginalController.LowPart & 0xFFFF);
			ULONG count = irpStack->Parameters.Read.Length;
			Information = count;
			PUCHAR dst = currentAddress;

			// Enable input mode
			UCHAR v = READ_PORT_UCHAR(addr + 2);
			WRITE_PORT_UCHAR(addr + 2, v | 0x20);

			// Read each byte
			UCHAR orgCtl = READ_PORT_UCHAR(addr + 2);
			do {
				WRITE_PORT_UCHAR(addr + 2, orgCtl | 0x02);
				*dst++ = READ_PORT_UCHAR(addr);
				WRITE_PORT_UCHAR(addr + 2, orgCtl & (~0x02));
			} while (--count);

			// Disable input mode
			v = READ_PORT_UCHAR(addr + 2);
			WRITE_PORT_UCHAR(addr + 2, v & (~0x20));

			break;
		}
		case 3: {
			// EPP mode
			PUCHAR addr = (PUCHAR)(pDevExt->OriginalController.LowPart & 0xFFFF);
			ULONG count = irpStack->Parameters.Read.Length;
			Information = count;
			PUCHAR dst = currentAddress;
			do {
				*dst++ = READ_PORT_UCHAR(addr + 4);
			} while (--count);

			break;
		}

		}
	}

	Irp->IoStatus.Information = Information;
	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

NTSTATUS
GICParDispatchWrite(
	IN PDEVICE_OBJECT pDevObj,
	IN PIRP Irp
)
{
	PAGED_CODE();

	PIO_STACK_LOCATION          irpStack;
	PDEVICE_EXTENSION pDevExt = pDevObj->DeviceExtension;

	if (!pDevExt) {
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	irpStack = IoGetCurrentIrpStackLocation(Irp);

	if (irpStack->MajorFunction == IRP_MJ_WRITE) {
		PUCHAR currentAddress = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

		if (!currentAddress) {
			Irp->IoStatus.Information = 0;
			Irp->IoStatus.Status = STATUS_SUCCESS;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return STATUS_SUCCESS;
		}

		// irpStack->Parameters.Write.ByteOffset.LowPart, currentAddress, irpStack->Parameters.Write.Length;
	}

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS
GICParDispatchCleanup(
	IN PDEVICE_OBJECT pDevObj,
	IN PIRP Irp
)
{
	PAGED_CODE();

	PDEVICE_EXTENSION pDevExt = pDevObj->DeviceExtension;
	if (!pDevExt) {
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


NTSTATUS
GICParDispatchShutdown(
	IN PDEVICE_OBJECT pDevObj,
	IN PIRP Irp
)
{
	PAGED_CODE();

	PDEVICE_EXTENSION pDevExt = pDevObj->DeviceExtension;
	if (!pDevExt) {
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

#define IOCTL_GET_VER           CTL_CODE(0x8000, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_SPP_DATA     CTL_CODE(0x8000, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_STATUS       CTL_CODE(0x8000, 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_CONTROL      CTL_CODE(0x8000, 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_EPP_ADDRESS  CTL_CODE(0x8000, 5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_EPP_DATA     CTL_CODE(0x8000, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_SPP_DATA    CTL_CODE(0x8000, 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_STATUS      CTL_CODE(0x8000, 8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_CONTROL     CTL_CODE(0x8000, 9, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_EPP_ADDRESS CTL_CODE(0x8000,10, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_EPP_DATA    CTL_CODE(0x8000,11, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_READLINE_MODE CTL_CODE(0x8000,12, METHOD_BUFFERED, FILE_ANY_ACCESS)


NTSTATUS 
GICParDispatchIoCtl(
	IN PDEVICE_OBJECT pDevObj, 
	IN PIRP Irp
) 
{
	PAGED_CODE();

	PIO_STACK_LOCATION  stkloc;
	ULONG               inBuffersize;
	ULONG               outBuffersize;
	PVOID               CtrlBuff;
	NTSTATUS			Status = STATUS_SUCCESS;
	ULONG_PTR           Information = 0;

	PDEVICE_EXTENSION   pDevExt = pDevObj->DeviceExtension;
	if (!pDevExt) {
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	stkloc = IoGetCurrentIrpStackLocation(Irp);
	inBuffersize = stkloc->Parameters.DeviceIoControl.InputBufferLength;
	outBuffersize = stkloc->Parameters.DeviceIoControl.OutputBufferLength;
	CtrlBuff = Irp->AssociatedIrp.SystemBuffer;

	switch (stkloc->Parameters.DeviceIoControl.IoControlCode)
	{
		case IOCTL_GET_VER           :
			if (outBuffersize != 4)
				Status = STATUS_INVALID_PARAMETER;
			break;
		case IOCTL_READ_SPP_DATA     :
			if (outBuffersize != 1) {
				Status = STATUS_INVALID_PARAMETER;
			} else {
				PUCHAR addr = (PUCHAR)(pDevExt->OriginalController.LowPart & 0xFFFF);
				((PUCHAR)(CtrlBuff))[0] = READ_PORT_UCHAR(addr);
				Information = 1;
			}
			break;
		case IOCTL_READ_STATUS       :
			if (outBuffersize != 1) {
				Status = STATUS_INVALID_PARAMETER;
			}
			else {
				PUCHAR addr = (PUCHAR)(pDevExt->OriginalController.LowPart & 0xFFFF);
				((PUCHAR)(CtrlBuff))[0] = READ_PORT_UCHAR(addr+1);
				Information = 1;
			}
			break;
		case IOCTL_READ_CONTROL      :
			if (outBuffersize != 1) {
				Status = STATUS_INVALID_PARAMETER;
			}
			else {
				PUCHAR addr = (PUCHAR)(pDevExt->OriginalController.LowPart & 0xFFFF);
				((PUCHAR)(CtrlBuff))[0] = READ_PORT_UCHAR(addr+2);
				Information = 1;
			}
			break;
		case IOCTL_READ_EPP_ADDRESS  :
			if (outBuffersize != 1) {
				Status = STATUS_INVALID_PARAMETER;
			}
			else {
				PUCHAR addr = (PUCHAR)(pDevExt->OriginalController.LowPart & 0xFFFF);
				((PUCHAR)(CtrlBuff))[0] = READ_PORT_UCHAR(addr+3);
				Information = 1;
			}
			break;
		case IOCTL_READ_EPP_DATA     :
			if (outBuffersize != 1) {
				Status = STATUS_INVALID_PARAMETER;
			}
			else {
				PUCHAR addr = (PUCHAR)(pDevExt->OriginalController.LowPart & 0xFFFF);
				((PUCHAR)(CtrlBuff))[0] = READ_PORT_UCHAR(addr+4);
				Information = 1;
			}
			break;
		case IOCTL_WRITE_SPP_DATA    :
			if (inBuffersize != 1) {
				Status = STATUS_INVALID_PARAMETER;
			}
			else {
				PUCHAR addr = (PUCHAR)(pDevExt->OriginalController.LowPart & 0xFFFF);
				WRITE_PORT_UCHAR(addr, ((PUCHAR)(CtrlBuff))[0]);
			}
			break;
		case IOCTL_WRITE_STATUS      :
			if (inBuffersize != 1) {
				Status = STATUS_INVALID_PARAMETER;
			}
			else {
				PUCHAR addr = (PUCHAR)(pDevExt->OriginalController.LowPart & 0xFFFF);
				WRITE_PORT_UCHAR(addr+1, ((PUCHAR)(CtrlBuff))[0]);
			}
			break;
		case IOCTL_WRITE_CONTROL     :
			if (inBuffersize != 1) {
				Status = STATUS_INVALID_PARAMETER;
			}
			else {
				PUCHAR addr = (PUCHAR)(pDevExt->OriginalController.LowPart & 0xFFFF);
				WRITE_PORT_UCHAR(addr+2, ((PUCHAR)(CtrlBuff))[0]);
			}
			break;
		case IOCTL_WRITE_EPP_ADDRESS :
			if (inBuffersize != 1) {
				Status = STATUS_INVALID_PARAMETER;
			}
			else {
				PUCHAR addr = (PUCHAR)(pDevExt->OriginalController.LowPart & 0xFFFF);
				WRITE_PORT_UCHAR(addr+3, ((PUCHAR)(CtrlBuff))[0]);
			}
			break;
		case IOCTL_WRITE_EPP_DATA    :
			if (inBuffersize != 1) {
				Status = STATUS_INVALID_PARAMETER;
			}
			else {
				PUCHAR addr = (PUCHAR)(pDevExt->OriginalController.LowPart & 0xFFFF);
				WRITE_PORT_UCHAR(addr+4, ((PUCHAR)(CtrlBuff))[0]);
			}
			break;
		case IOCTL_SET_READLINE_MODE :
			if (inBuffersize != 1) {
				Status = STATUS_INVALID_PARAMETER;
			}
			else {
				pDevExt->LineReadMode =  ((PUCHAR)(CtrlBuff))[0];
			}
			break;
	}

	Irp->IoStatus.Information = Information;
	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

VOID     
GICParDriverUnload(
	IN PDRIVER_OBJECT  pDriverObject
)
{
	// Initialize a Device object for each parallel port
	ULONG NtDeviceNumber, NumParallelPorts = IoGetConfigurationInformation()->ParallelCount;
	for (NtDeviceNumber = 0; NtDeviceNumber < NumParallelPorts; NtDeviceNumber++)
	{
		GICParDeleteDevice(pDriverObject, NtDeviceNumber);
	}
}

NTSTATUS
DriverEntry(
	IN PDRIVER_OBJECT pDriverObject,
	IN PUNICODE_STRING pRegistryPath
)
{
	ULONG NtDeviceNumber, NumParallelPorts;
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(pRegistryPath);

	// Export other driver entry points...
	pDriverObject->DriverUnload = GICParDriverUnload;

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = GICParDispatchOpen;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = GICParDispatchClose;
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = GICParDispatchWrite;
	pDriverObject->MajorFunction[IRP_MJ_READ] = GICParDispatchRead;
	pDriverObject->MajorFunction[IRP_MJ_CLEANUP] = GICParDispatchCleanup;
	pDriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = GICParDispatchShutdown;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = GICParDispatchIoCtl;

	// Initialize a Device object for each parallel port
	NumParallelPorts = IoGetConfigurationInformation()->ParallelCount;

	for (NtDeviceNumber = 0; NtDeviceNumber < NumParallelPorts; NtDeviceNumber++)
	{
		status = GICParCreateDevice(pDriverObject, NtDeviceNumber);
		if (!NT_SUCCESS(status))
			return status;
	}

	// Log that we've started
	// ...

	return status;
}

static NTSTATUS
GICParCreateDevice(
	IN PDRIVER_OBJECT pDriverObject,
	IN ULONG NtDeviceNumber
)
{
	NTSTATUS status;

	PDEVICE_OBJECT pDevObj;
	PDEVICE_EXTENSION pDevExt;

	UNICODE_STRING deviceName, portName, linkName, number;
	WCHAR deviceNameBuffer[GICPAR_MAX_NAME_LENGTH];
	WCHAR portNameBuffer[GICPAR_MAX_NAME_LENGTH];
	WCHAR linkNameBuffer[GICPAR_MAX_NAME_LENGTH];
	WCHAR numberBuffer[10];

	PFILE_OBJECT        pFileObject;

	// Initialise strings
	number.Buffer = numberBuffer;
	number.MaximumLength = 20;
	deviceName.Buffer = deviceNameBuffer;
	deviceName.MaximumLength = GICPAR_MAX_NAME_LENGTH * 2;
	portName.Buffer = portNameBuffer;
	portName.MaximumLength = GICPAR_MAX_NAME_LENGTH * 2;
	linkName.Buffer = linkNameBuffer;
	linkName.MaximumLength = GICPAR_MAX_NAME_LENGTH * 2;

	/////////////////////////////////////////////////////////////////////////
	// Form the base NT device name...

	deviceName.Length = 0;
	RtlAppendUnicodeToString(&deviceName, GICPAR_NT_DEVICE_NAME);
	number.Length = 0;
	RtlIntegerToUnicodeString(NtDeviceNumber, 10, &number);
	RtlAppendUnicodeStringToString(&deviceName, &number);

	// Create a Device object for this device...
	status = IoCreateDevice(
		pDriverObject,
		sizeof(DEVICE_EXTENSION),
		&deviceName,
		FILE_DEVICE_PARALLEL_PORT,
		0,
		TRUE,
		&pDevObj);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	/////////////////////////////////////////////////////////////////////////
	// Use buffered I/O
	pDevObj->Flags |= DO_BUFFERED_IO;
	pDevObj->Flags &= ~DO_DEVICE_INITIALIZING;

	/////////////////////////////////////////////////////////////////////////
	// Initialize the Device Extension

	pDevExt = pDevObj->DeviceExtension;
	pDevExts[NtDeviceNumber] = pDevExt;
	RtlZeroMemory(pDevExt, sizeof(DEVICE_EXTENSION));

	pDevExt->DeviceObject = pDevObj;
	pDevExt->NtDeviceNumber = NtDeviceNumber;

	/////////////////////////////////////////////////////////////////////////
	// Attach to parport device
	portName.Length = 0;
	RtlAppendUnicodeToString(&portName, GICPAR_NT_PORT_DEVICE_NAME);
	number.Length = 0;
	RtlIntegerToUnicodeString(NtDeviceNumber, 10, &number);
	RtlAppendUnicodeStringToString(&portName, &number);

	status = IoGetDeviceObjectPointer(&portName, FILE_READ_ATTRIBUTES,
		&pFileObject,
		&pDevExt->PortDeviceObject);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDevObj);
		pDevExts[NtDeviceNumber] = NULL;
		return status;
	}

	ObReferenceObjectByPointer(pDevExt->PortDeviceObject, FILE_READ_ATTRIBUTES, NULL, KernelMode);
	ObDereferenceObject(pFileObject);
	pDevExt->DeviceObject->StackSize = pDevExt->PortDeviceObject->StackSize + 1;

	// Get the port information from the port device object.
	status = GICParGetPortInfoFromPortDevice(pDevExt);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDevObj);
		pDevExts[NtDeviceNumber] = NULL;
		return status;
	}

	/////////////////////////////////////////////////////////////////////////
	// Form the Win32 symbolic link name.
	linkName.Length = 0;
	RtlAppendUnicodeToString(&linkName, GICPAR_WIN32_DEVICE_NAME);
	number.Length = 0;
	RtlIntegerToUnicodeString(NtDeviceNumber, 10, &number);
	RtlAppendUnicodeStringToString(&linkName, &number);

	// Create a symbolic link so our device is visible to Win32...
	status = IoCreateSymbolicLink(&linkName, &deviceName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDevObj);
		pDevExts[NtDeviceNumber] = NULL;
		return status;
	}

	return status;
}

static VOID
GICParDeleteDevice(
	IN PDRIVER_OBJECT pDriverObject,
	IN ULONG NtDeviceNumber
)
{
	PDEVICE_OBJECT pDevObj;
	PDEVICE_EXTENSION pDevExt;
	UNREFERENCED_PARAMETER(pDriverObject);

	UNICODE_STRING linkName, number;
	WCHAR linkNameBuffer[GICPAR_MAX_NAME_LENGTH];
	WCHAR numberBuffer[10];

	// Get the associated device extension
	pDevExt = pDevExts[NtDeviceNumber];
	if (!pDevExt)
		return;
	pDevObj = pDevExt->DeviceObject;

	// Initialise strings
	number.Buffer = numberBuffer;
	number.MaximumLength = 20;
	linkName.Buffer = linkNameBuffer;
	linkName.MaximumLength = GICPAR_MAX_NAME_LENGTH * 2;

	/////////////////////////////////////////////////////////////////////////
	// Detach from parport device
	ObDereferenceObject(pDevExt->PortDeviceObject);

	/////////////////////////////////////////////////////////////////////////
	// Form the Win32 symbolic link name.
	linkName.Length = 0;
	RtlAppendUnicodeToString(&linkName, GICPAR_WIN32_DEVICE_NAME);
	number.Length = 0;
	RtlIntegerToUnicodeString(NtDeviceNumber, 10, &number);
	RtlAppendUnicodeStringToString(&linkName, &number);

	// Delete the symbolic link...
	IoDeleteSymbolicLink(&linkName);

	// And delete the device
	IoDeleteDevice(pDevObj);

	pDevExts[NtDeviceNumber] = NULL;
}

static NTSTATUS
GICParGetPortInfoFromPortDevice(
	IN OUT  PDEVICE_EXTENSION   pDevExt
)
{
	KEVENT                      event;
	PIRP                        irp;
	PARALLEL_PORT_INFORMATION   portInfo;
	IO_STATUS_BLOCK             ioStatus;
	NTSTATUS                    status;

	/////////////////////////////////////////////////////////////////////////
	// Get parallel port information

	KeInitializeEvent(&event, NotificationEvent, FALSE);

	irp = IoBuildDeviceIoControlRequest(
		IOCTL_INTERNAL_GET_PARALLEL_PORT_INFO,
		pDevExt->PortDeviceObject,
		NULL, 0, &portInfo,
		sizeof(PARALLEL_PORT_INFORMATION),
		TRUE, &event, &ioStatus);

	if (!irp)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = IoCallDriver(pDevExt->PortDeviceObject, irp);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	pDevExt->OriginalController = portInfo.OriginalController;
	pDevExt->Controller = portInfo.Controller;
	pDevExt->SpanOfController = portInfo.SpanOfController;
	pDevExt->FreePort = portInfo.FreePort;
	pDevExt->TryAllocatePort = portInfo.TryAllocatePort;
	pDevExt->PortContext = portInfo.Context;

	// Check register span
	if (pDevExt->SpanOfController < GICPAR_REGISTER_SPAN)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	return STATUS_SUCCESS;
}