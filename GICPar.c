#include "ntddk.h"
#include "parallel.h"

// Debugging Aids
//#define ENABLE_DEBUGGING        1
#define LOG_TOFILE				1									/* Used to log ALL debug messages to a file (don't use it with a debugger) */
#define DEFAULT_LOG_FILE_NAME	L"\\??\\C:\\logs\\GICPar.log"		/* The log filename */

typedef struct {
	char buf[65536]; // Character buffer
	LONG FirstToGet; // First char to get...
	LONG FirstFree;	 // And the first free char..
} dbg_queue;

// The prototype of the generalized printf-like proto
static int dbg_printf(dbg_queue* p, char* control, int* argptr);

// This fn is our DbgPrint-like fn that logs with extra logging facilities!
static void LogPrint(char* szFormat, ...)
{
#ifdef LOG_TOFILE

	// Our print buffer... 
	static dbg_queue dq = { {0},0L,0L };

	// Print the debug message in the debug Queue...
	// And then, the things we need...
	dbg_printf(&dq, szFormat, (int*)(&szFormat + 1));

	// If we were called at passive level, we can actually do the log dump - Do it!
	if (KeGetCurrentIrql() == PASSIVE_LEVEL) {

		IO_STATUS_BLOCK  IoStatus;
		OBJECT_ATTRIBUTES objectAttributes;
		NTSTATUS status;
		HANDLE FileHandle;
		UNICODE_STRING fileName;

		// get a handle to the log file object
		fileName.Buffer = NULL;
		fileName.Length = 0;
		fileName.MaximumLength = sizeof(DEFAULT_LOG_FILE_NAME) + sizeof(UNICODE_NULL);
		fileName.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, fileName.MaximumLength,' gbd');
		if (!fileName.Buffer)
		{
			return;
		}

		RtlZeroMemory(fileName.Buffer, fileName.MaximumLength);
		status = RtlAppendUnicodeToString(&fileName, (PWSTR)DEFAULT_LOG_FILE_NAME);

		InitializeObjectAttributes(&objectAttributes,
			(PUNICODE_STRING)&fileName,
			OBJ_CASE_INSENSITIVE,
			NULL,
			NULL);

		status = ZwCreateFile(&FileHandle,
			FILE_APPEND_DATA,
			&objectAttributes,
			&IoStatus,
			0,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_WRITE,
			FILE_OPEN_IF,
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);

		if (NT_SUCCESS(status)) {
			// While there is something to write...
			while (((dq.FirstFree - dq.FirstToGet) & 0xFFFF) != 0) {

				LONG Pos = (InterlockedIncrement(&dq.FirstToGet) - 1) & 0xFFFF;
				CHAR c = (CHAR)dq.buf[Pos];

				ZwWriteFile(FileHandle,
					NULL,
					NULL,
					NULL,
					&IoStatus,
					&c,
					1,
					NULL,
					NULL);
			};

			ZwClose(FileHandle);
		}
		if (fileName.Buffer) {
			ExFreePool(fileName.Buffer);
		}
	}
#else
	UNREFERENCED_PARAMETER(szFormat);
#endif
}

#ifdef LOG_TOFILE

// Here it follows an alternative sprintf-like fn but with buffer overflow protection...
// so we can redirect Debug output...

// Written by: Philip J. Erdelsky, 75746.3411@compuserve.com
// Date:          06-08-1992
// Restrictions:  Public domain; no restrictions on use 

#define BITS_PER_BYTE           8

struct parameters {
	int number_of_output_chars;
	short minimum_field_width;
	char options;
#define MINUS_SIGN    1
#define RIGHT_JUSTIFY 2
#define ZERO_PAD      4
#define CAPITAL_HEX   8
	short edited_string_length;
	short leading_zeros;
	int (*output_function)(void*, int);
	void* output_pointer;
};

static void output_and_count(struct parameters* p, int c)
{
	if (p->number_of_output_chars >= 0)
	{
		int n = (*p->output_function)(p->output_pointer, c);
		if (n >= 0) p->number_of_output_chars++;
		else p->number_of_output_chars = n;
	}
}

static void output_field(struct parameters* p, char* s)
{
	short justification_length =
		p->minimum_field_width - p->leading_zeros - p->edited_string_length;
	if (p->options & MINUS_SIGN)
	{
		if (p->options & ZERO_PAD)
			output_and_count(p, '-');
		justification_length--;
	}
	if (p->options & RIGHT_JUSTIFY)
		while (--justification_length >= 0)
			output_and_count(p, p->options & ZERO_PAD ? '0' : ' ');
	if (p->options & MINUS_SIGN && !(p->options & ZERO_PAD))
		output_and_count(p, '-');
	while (--p->leading_zeros >= 0)
		output_and_count(p, '0');
	while (--p->edited_string_length >= 0)
		output_and_count(p, *s++);
	while (--justification_length >= 0)
		output_and_count(p, ' ');
}

static int general_printf(int (*output_function)(void*, int), void* output_pointer,
	char* control_string, int* argument_pointer)
{
	struct parameters p;
	char control_char;
	p.number_of_output_chars = 0;
	p.output_function = output_function;
	p.output_pointer = output_pointer;
	control_char = *control_string++;
	while (control_char != '\0')
	{
		if (control_char == '%')
		{
			short precision = -1;
			short long_argument = 0;
			short base = 0;
			control_char = *control_string++;
			p.minimum_field_width = 0;
			p.leading_zeros = 0;
			p.options = RIGHT_JUSTIFY;
			if (control_char == '-')
			{
				p.options = 0;
				control_char = *control_string++;
			}
			if (control_char == '0')
			{
				p.options |= ZERO_PAD;
				control_char = *control_string++;
			}
			if (control_char == '*')
			{
				p.minimum_field_width = (short)*argument_pointer++;
				control_char = *control_string++;
			}
			else
			{
				while ('0' <= control_char && control_char <= '9')
				{
					p.minimum_field_width =
						p.minimum_field_width * 10 + control_char - '0';
					control_char = *control_string++;
				}
			}
			if (control_char == '.')
			{
				control_char = *control_string++;
				if (control_char == '*')
				{
					precision = (short)*argument_pointer++;
					control_char = *control_string++;
				}
				else
				{
					precision = 0;
					while ('0' <= control_char && control_char <= '9')
					{
						precision = precision * 10 + control_char - '0';
						control_char = *control_string++;
					}
				}
			}
			if (control_char == 'l')
			{
				long_argument = 1;
				control_char = *control_string++;
			}
			if (control_char == 'd')
				base = 10;
			else if (control_char == 'x')
				base = 16;
			else if (control_char == 'X')
			{
				base = 16;
				p.options |= CAPITAL_HEX;
			}
			else if (control_char == 'u')
				base = 10;
			else if (control_char == 'o')
				base = 8;
			else if (control_char == 'b')
				base = 2;
			else if (control_char == 'c')
			{
				base = -1;
				p.options &= ~ZERO_PAD;
			}
			else if (control_char == 's')
			{
				base = -2;
				p.options &= ~ZERO_PAD;
			}
			if (base == 0)  /* invalid conversion type */
			{
				if (control_char != '\0')
				{
					output_and_count(&p, control_char);
					control_char = *control_string++;
				}
			}
			else
			{
				if (base == -1)  /* conversion type c */
				{
					char c = (char)*argument_pointer++;
					p.edited_string_length = 1;
					output_field(&p, &c);
				}
				else if (base == -2)  /* conversion type s */
				{
					char* string;
					p.edited_string_length = 0;
					string = *(char**)argument_pointer;
					argument_pointer += sizeof(char*) / sizeof(int);
					while (string[p.edited_string_length] != 0)
						p.edited_string_length++;
					if (precision >= 0 && p.edited_string_length > precision)
						p.edited_string_length = precision;
					output_field(&p, string);
				}
				else  /* conversion type d, b, o or x */
				{
					unsigned long x;
					char buffer[BITS_PER_BYTE * sizeof(unsigned long) + 1];
					p.edited_string_length = 0;
					if (long_argument)
					{
						x = *(unsigned long*)argument_pointer;
						argument_pointer += sizeof(unsigned long) / sizeof(int);
					}
					else if (control_char == 'd')
						x = (long)*argument_pointer++;
					else
						x = (unsigned)*argument_pointer++;
					if (control_char == 'd' && (long)x < 0)
					{
						p.options |= MINUS_SIGN;
						x = -(long)x;
					}
					do
					{
						int c;
						c = x % base + '0';
						if (c > '9')
						{
							if (p.options & CAPITAL_HEX)
								c += 'A' - '9' - 1;
							else
								c += 'a' - '9' - 1;
						}
						buffer[sizeof(buffer) - 1 - p.edited_string_length++] = (char)c;
					} while ((x /= base) != 0);
					if (precision >= 0 && precision > p.edited_string_length)
						p.leading_zeros = precision - p.edited_string_length;
					output_field(&p, buffer + sizeof(buffer) - p.edited_string_length);
				}
				control_char = *control_string++;
			}
		}
		else
		{
			output_and_count(&p, control_char);
			control_char = *control_string++;
		}
	}
	return p.number_of_output_chars;
}

static int fill_string(void* p, int c)
{
	dbg_queue* dq = (dbg_queue*)p;

	// If not full, insert char into queue
	if (((dq->FirstFree - dq->FirstToGet + 1) & 0xFFFF) != 0) {
		LONG Pos = (InterlockedIncrement(&dq->FirstFree) - 1) & 0xFFFF;
		dq->buf[Pos] = (char)c;
	}
	return 0;
}

static int dbg_printf(dbg_queue* p, char* control, int* argptr)
{
	int n = general_printf(fill_string, p, control, argptr);
	return n;
}
#endif

#ifdef ENABLE_DEBUGGING
static void DbgTimeStamp()
{
	// Get current system time...
	LARGE_INTEGER time;
	KeQuerySystemTime(&time);

	// And output the TimeStamp info
	DbgPrint("%10u-%10u|", time.HighPart, time.LowPart);
	LogPrint("%10u-%10u|", time.HighPart, time.LowPart);
}

#define LOG(x) \
	do { \
		DbgTimeStamp(); \
		DbgPrint x ; \
		LogPrint x ; \
		LogPrint("\n"); \
	} while(0)
#else

#define LOG(x)

#endif

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

	PHYSICAL_ADDRESS                OriginalEcpController;
	PUCHAR                          EcpController;
	ULONG                           SpanOfEcpController;
	PHYSICAL_ADDRESS                EppControllerPhysicalAddress;
	ULONG                           SpanOfEppController;
	ULONG                           HardwareCapabilities;
	PPARALLEL_SET_CHIP_MODE         TrySetChipMode;		// Callback to set chip mode
	PPARALLEL_CLEAR_CHIP_MODE       ClearChipMode;		// Callback to clear chip mode
	PVOID                           PnPContext;
	UCHAR                           CurrentMode;

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
	LOG((__FUNCTION__));

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
			LOG(("ERROR: Unable to AllocatePort"));

			// Unable to open it. Fail the opening
			Irp->IoStatus.Information = 0;
			Irp->IoStatus.Status = STATUS_ADAPTER_HARDWARE_ERROR;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return STATUS_ADAPTER_HARDWARE_ERROR;
		}

		// If dealing with an ECP port
		if (pDevExt->SpanOfEcpController >= ECP_SPAN) {
			LOG(("ECP port: Trying to switch it to EPP"));

			// If port supports ECP mode, try to switch it to EPP emulation

			if ((pDevExt->HardwareCapabilities & PPT_ECP_PRESENT) != 0) {
				LOG(("Parallel port: ECP Capable"));

				// We probably have a controllable ECP port. Switch it to EPP mode
				if (pDevExt->ClearChipMode)
					if (pDevExt->ClearChipMode(pDevExt->PnPContext, pDevExt->CurrentMode) == STATUS_SUCCESS)
						pDevExt->CurrentMode = HW_MODE_COMPATIBILITY;
					else {
						LOG(("ERROR: Unable to ClearChipMode"));
					}

				if (pDevExt->TrySetChipMode)
					if (pDevExt->TrySetChipMode(pDevExt->PnPContext, HW_MODE_EPP) == STATUS_SUCCESS)
						pDevExt->CurrentMode = HW_MODE_EPP;
					else {
						LOG(("ERROR: Unable to TrySetChipMode"));
					}

				// Switch port to EPP mode if possible
				PUCHAR ecpBaseAddr = (PUCHAR)pDevExt->OriginalEcpController.QuadPart;
				WRITE_PORT_UCHAR(ecpBaseAddr + 2, ECR_EPP_PIO_MODE);
			}
			else {

				// If port supports EPP/EPP32 mode, try to switch to it
				if ((pDevExt->HardwareCapabilities & PPT_EPP_PRESENT) != 0 || (pDevExt->HardwareCapabilities & PPT_EPP_32_PRESENT) != 0) {
					LOG(("Parallel port: EPP Capable"));

					// We probably have a controllable ECP port. Switch it to EPP mode
					if (pDevExt->ClearChipMode)
						if (pDevExt->ClearChipMode(pDevExt->PnPContext, pDevExt->CurrentMode) == STATUS_SUCCESS)
							pDevExt->CurrentMode = HW_MODE_COMPATIBILITY;
						else {
							LOG(("ERROR: Unable to ClearChipMode"));
						}

					if (pDevExt->TrySetChipMode)
						if (pDevExt->TrySetChipMode(pDevExt->PnPContext, HW_MODE_EPP) == STATUS_SUCCESS)
							pDevExt->CurrentMode = HW_MODE_EPP;
						else {
							LOG(("ERROR: Unable to TrySetChipMode"));
						}

					// Switch port to EPP mode if possible
					PUCHAR ecpBaseAddr = (PUCHAR)pDevExt->OriginalEcpController.QuadPart;
					WRITE_PORT_UCHAR(ecpBaseAddr + 2, ECR_EPP_PIO_MODE);
				}
				else {
					if ((pDevExt->HardwareCapabilities & PPT_BYTE_PRESENT) != 0) {
						LOG(("Parallel port: PS2 Capable"));

						// We probably have a controllable ECP port. Switch it to BYTE mode
						if (pDevExt->ClearChipMode)
							if (pDevExt->ClearChipMode(pDevExt->PnPContext, pDevExt->CurrentMode) == STATUS_SUCCESS)
								pDevExt->CurrentMode = HW_MODE_COMPATIBILITY;
							else {
								LOG(("ERROR: Unable to ClearChipMode"));
							}

						if (pDevExt->TrySetChipMode)
							if (pDevExt->TrySetChipMode(pDevExt->PnPContext, HW_MODE_PS2) == STATUS_SUCCESS)
								pDevExt->CurrentMode = HW_MODE_PS2;
							else {
								LOG(("ERROR: Unable to TrySetChipMode"));
							}

						// Switch port to BYTE mode if possible
						PUCHAR ecpBaseAddr = (PUCHAR)pDevExt->OriginalEcpController.QuadPart;
						WRITE_PORT_UCHAR(ecpBaseAddr + 2, ECR_BYTE_PIO_MODE);
					}
					else {
						LOG(("Parallel port: SPP Capable"));

						// We probably have a controllable ECP port. Switch it to SPP mode
						if (pDevExt->ClearChipMode)
							if (pDevExt->ClearChipMode(pDevExt->PnPContext, pDevExt->CurrentMode) == STATUS_SUCCESS)
								pDevExt->CurrentMode = HW_MODE_COMPATIBILITY;
							else {
								LOG(("ERROR: Unable to ClearChipMode"));
							}

						if (pDevExt->TrySetChipMode)
							if (pDevExt->TrySetChipMode(pDevExt->PnPContext, HW_MODE_COMPATIBILITY) == STATUS_SUCCESS)
								pDevExt->CurrentMode = HW_MODE_COMPATIBILITY;
							else {
								LOG(("ERROR: Unable to TrySetChipMode"));
							}

						// Switch port to SPP mode if possible
						PUCHAR ecpBaseAddr = (PUCHAR)pDevExt->OriginalEcpController.QuadPart;
						WRITE_PORT_UCHAR(ecpBaseAddr + 2, ECR_SPP_MODE);
					}
				}
			}
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
	LOG((__FUNCTION__));

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
	LOG((__FUNCTION__));

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
		PUCHAR currentAddress = Irp->AssociatedIrp.SystemBuffer; // for DO_BUFFERED_IO 
			//MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

		if (!currentAddress || irpStack->Parameters.Read.Length == 0) {
			LOG(("ERROR: NULL address or count == 0"));

			Irp->IoStatus.Information = 0;
			Irp->IoStatus.Status = STATUS_SUCCESS;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return STATUS_SUCCESS;
		}

		// Depending on Scanner read mode, do
		switch (pDevExt->LineReadMode) {
		case 1: {
			// SPP mode
			PUCHAR baseAddr = (PUCHAR)pDevExt->OriginalController.QuadPart;
			ULONG count = irpStack->Parameters.Read.Length;
			LOG(("SPP readline: baseAddress: 0x%08x, count: %d", (int)(UINT64)baseAddr, count));
			Information = count;
			PUCHAR dst = currentAddress;

			WRITE_PORT_UCHAR(baseAddr, 0xFF);

			UCHAR orgCtl = READ_PORT_UCHAR(baseAddr + 2);
			do {
				WRITE_PORT_UCHAR(baseAddr + 2, orgCtl | (0x2 | 0x8));
				UCHAR rd1 = READ_PORT_UCHAR(baseAddr + 1);
				WRITE_PORT_UCHAR(baseAddr + 2, orgCtl & (~0x8));
				UCHAR rd2 = READ_PORT_UCHAR(baseAddr + 1);
				WRITE_PORT_UCHAR(baseAddr + 2, orgCtl & (~0x2));
				*dst++ = (rd2 >> 4) | (rd1 & 0xF0);
			} while (--count);
			break;
		}
		case 2: {
			// PS2 mode
			PUCHAR baseAddr = (PUCHAR)pDevExt->OriginalController.QuadPart;
			ULONG count = irpStack->Parameters.Read.Length;
			LOG(("PS2 readline: baseAddress: 0x%08x, count: %d", (int)(UINT64)baseAddr, count));
			Information = count;
			PUCHAR dst = currentAddress;

			// Enable input mode
			UCHAR v = READ_PORT_UCHAR(baseAddr + 2);
			WRITE_PORT_UCHAR(baseAddr + 2, v | 0x20);

			// Read each byte
			UCHAR orgCtl = READ_PORT_UCHAR(baseAddr + 2);
			do {
				WRITE_PORT_UCHAR(baseAddr + 2, orgCtl | 0x02);
				*dst++ = READ_PORT_UCHAR(baseAddr);
				WRITE_PORT_UCHAR(baseAddr + 2, orgCtl & (~0x02));
			} while (--count);

			// Disable input mode
			v = READ_PORT_UCHAR(baseAddr + 2);
			WRITE_PORT_UCHAR(baseAddr + 2, v & (~0x20));

			break;
		}
		case 3: {
			// EPP mode
			PUCHAR eppBaseAddr = (pDevExt->SpanOfEppController > 0 && pDevExt->EppControllerPhysicalAddress.QuadPart != 0)
				? (PUCHAR)pDevExt->EppControllerPhysicalAddress.QuadPart
				: (PUCHAR)pDevExt->OriginalController.QuadPart + 4;
			ULONG count = irpStack->Parameters.Read.Length;
			LOG(("EPP readline: eppBaseAddress: 0x%08x, count: %d", (int)(UINT64)eppBaseAddr, count));
			Information = count;
			PUCHAR dst = currentAddress;

			// Try to do 32bit io, if parallel port allows it
			if (pDevExt->CurrentMode == HW_MODE_EPP && (pDevExt->HardwareCapabilities & PPT_EPP_32_PRESENT) != 0) {
#if 0
				while (count >= 4) {
					*((PULONG)dst) = READ_PORT_ULONG((PULONG)eppBaseAddr);
					dst += 4;
					count -= 4;
				}
				while (count >= 2) {
					*((PUSHORT)dst) = READ_PORT_USHORT((PUSHORT)eppBaseAddr);
					dst += 2;
					count -= 2;
				}
				while (count >= 1) {
					*dst++ = READ_PORT_UCHAR((PUCHAR)eppBaseAddr);
					count -= 1;
				}
#else
				if (count >= 4) {
					READ_PORT_BUFFER_ULONG((PULONG)eppBaseAddr, (PULONG)dst, count >> 2);
					dst += count & 0xFFFFFFFCUL;
					count &= 3;
				}
				if (count >= 2) {
					READ_PORT_BUFFER_USHORT((PUSHORT)eppBaseAddr, (PUSHORT)dst, count >> 1);
					dst += count & 0xFFFFFFFEUL;
					count &= 1;
				}
				if (count >= 1) {
					READ_PORT_BUFFER_UCHAR((PUCHAR)eppBaseAddr, (PUCHAR)dst, count);
					dst += count;
					count = 0;
				}
#endif
			}
			else {
#if 0
				do {
					*dst++ = READ_PORT_UCHAR(eppBaseAddr);
				} while (--count);
#else
				// Get the byte string as fast as possible
				READ_PORT_BUFFER_UCHAR(eppBaseAddr, dst, count);
#endif
			}

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
	LOG((__FUNCTION__));

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
		PUCHAR currentAddress = Irp->AssociatedIrp.SystemBuffer; // for DO_BUFFERED_IO 
		//MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

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
	LOG((__FUNCTION__));

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
	LOG((__FUNCTION__));

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
	LOG((__FUNCTION__));

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
				LOG(("IOCTL_READ_SPP_DATA: Invalid parameter outBuffersize:%d", outBuffersize));
				Status = STATUS_INVALID_PARAMETER;
			} else {
				PUCHAR baseAddr = (PUCHAR)pDevExt->OriginalController.QuadPart;
				((PUCHAR)(CtrlBuff))[0] = READ_PORT_UCHAR(baseAddr);
				Information = 1;
				LOG(("IOCTL_READ_SPP_DATA: read 0x%02x from 0x%04x", ((PUCHAR)(CtrlBuff))[0], baseAddr));
			}
			break;
		case IOCTL_READ_STATUS       :
			if (outBuffersize != 1) {
				LOG(("IOCTL_READ_STATUS: Invalid parameter outBuffersize:%d", outBuffersize));
				Status = STATUS_INVALID_PARAMETER;
			}
			else {
				PUCHAR baseAddr = (PUCHAR)pDevExt->OriginalController.QuadPart;
				((PUCHAR)(CtrlBuff))[0] = READ_PORT_UCHAR(baseAddr+1);
				Information = 1;
				LOG(("IOCTL_READ_STATUS: read 0x%02x from 0x%04x", ((PUCHAR)(CtrlBuff))[0], baseAddr+1));
			}
			break;
		case IOCTL_READ_CONTROL      :
			if (outBuffersize != 1) {
				LOG(("IOCTL_READ_CONTROL: Invalid parameter outBuffersize:%d", outBuffersize));
				Status = STATUS_INVALID_PARAMETER;
			}
			else {
				PUCHAR baseAddr = (PUCHAR)pDevExt->OriginalController.QuadPart;
				((PUCHAR)(CtrlBuff))[0] = READ_PORT_UCHAR(baseAddr+2);
				Information = 1;
				LOG(("IOCTL_READ_CONTROL: read 0x%02x from 0x%04x", ((PUCHAR)(CtrlBuff))[0], baseAddr+2));
			}
			break;
		case IOCTL_READ_EPP_ADDRESS  :
			if (outBuffersize != 1) {
				LOG(("IOCTL_READ_EPP_ADDRESS: Invalid parameter outBuffersize:%d", outBuffersize));
				Status = STATUS_INVALID_PARAMETER;
			}
			else {
				PUCHAR baseAddr = (PUCHAR)pDevExt->OriginalController.QuadPart;
				((PUCHAR)(CtrlBuff))[0] = READ_PORT_UCHAR(baseAddr+3);
				Information = 1;
				LOG(("IOCTL_READ_EPP_ADDRESS: read 0x%02x from 0x%04x", ((PUCHAR)(CtrlBuff))[0], baseAddr + 3));
			}
			break;
		case IOCTL_READ_EPP_DATA     :
			if (outBuffersize != 1) {
				LOG(("IOCTL_READ_EPP_DATA: Invalid parameter outBuffersize:%d", outBuffersize));
				Status = STATUS_INVALID_PARAMETER;
			}
			else {
				PUCHAR eppBaseAddr = (pDevExt->SpanOfEppController > 0 && pDevExt->EppControllerPhysicalAddress.QuadPart != 0)
					? (PUCHAR)pDevExt->EppControllerPhysicalAddress.QuadPart
					: (PUCHAR)pDevExt->OriginalController.QuadPart + 4;

				((PUCHAR)(CtrlBuff))[0] = READ_PORT_UCHAR(eppBaseAddr);
				Information = 1;
				LOG(("IOCTL_READ_EPP_DATA: read 0x%02x from 0x%04x", ((PUCHAR)(CtrlBuff))[0], eppBaseAddr));
			}
			break;
		case IOCTL_WRITE_SPP_DATA    :
			if (inBuffersize != 1) {
				LOG(("IOCTL_WRITE_SPP_DATA: Invalid parameter inBuffersize:%d", inBuffersize));
				Status = STATUS_INVALID_PARAMETER;
			}
			else {
				PUCHAR baseAddr = (PUCHAR)pDevExt->OriginalController.QuadPart;
				WRITE_PORT_UCHAR(baseAddr, ((PUCHAR)(CtrlBuff))[0]);
				LOG(("IOCTL_WRITE_SPP_DATA: write 0x%02x to 0x%04x", ((PUCHAR)(CtrlBuff))[0], baseAddr));
			}
			break;
		case IOCTL_WRITE_STATUS      :
			if (inBuffersize != 1) {
				LOG(("IOCTL_WRITE_STATUS: Invalid parameter inBuffersize:%d", inBuffersize));
				Status = STATUS_INVALID_PARAMETER;
			}
			else {
				PUCHAR baseAddr = (PUCHAR)pDevExt->OriginalController.QuadPart;
				WRITE_PORT_UCHAR(baseAddr+1, ((PUCHAR)(CtrlBuff))[0]);
				LOG(("IOCTL_WRITE_STATUS: write 0x%02x to 0x%04x", ((PUCHAR)(CtrlBuff))[0], baseAddr+1));
			}
			break;
		case IOCTL_WRITE_CONTROL     :
			if (inBuffersize != 1) {
				LOG(("IOCTL_WRITE_CONTROL: Invalid parameter inBuffersize:%d", inBuffersize));
				Status = STATUS_INVALID_PARAMETER;
			}
			else {
				PUCHAR baseAddr = (PUCHAR)pDevExt->OriginalController.QuadPart;
				WRITE_PORT_UCHAR(baseAddr+2, ((PUCHAR)(CtrlBuff))[0]);
				LOG(("IOCTL_WRITE_CONTROL: write 0x%02x to 0x%04x", ((PUCHAR)(CtrlBuff))[0], baseAddr + 2));
			}
			break;
		case IOCTL_WRITE_EPP_ADDRESS :
			if (inBuffersize != 1) {
				LOG(("IOCTL_WRITE_EPP_ADDRESS: Invalid parameter inBuffersize:%d", inBuffersize));
				Status = STATUS_INVALID_PARAMETER;
			}
			else {
				PUCHAR baseAddr = (PUCHAR)pDevExt->OriginalController.QuadPart;
				WRITE_PORT_UCHAR(baseAddr+3, ((PUCHAR)(CtrlBuff))[0]);
				LOG(("IOCTL_WRITE_EPP_ADDRESS: write 0x%02x to 0x%04x", ((PUCHAR)(CtrlBuff))[0], baseAddr + 3));
			}
			break;
		case IOCTL_WRITE_EPP_DATA    :
			if (inBuffersize != 1) {
				LOG(("IOCTL_WRITE_EPP_DATA: Invalid parameter inBuffersize:%d", inBuffersize));
				Status = STATUS_INVALID_PARAMETER;
			}
			else {
				PUCHAR eppBaseAddr = (pDevExt->SpanOfEppController > 0 && pDevExt->EppControllerPhysicalAddress.QuadPart != 0)
					? (PUCHAR)pDevExt->EppControllerPhysicalAddress.QuadPart
					: (PUCHAR)pDevExt->OriginalController.QuadPart + 4;

				WRITE_PORT_UCHAR(eppBaseAddr, ((PUCHAR)(CtrlBuff))[0]);
				LOG(("IOCTL_WRITE_EPP_DATA: write 0x%02x to 0x%04x", ((PUCHAR)(CtrlBuff))[0], eppBaseAddr));
			}
			break;
		case IOCTL_SET_READLINE_MODE :
			if (inBuffersize != 1) {
				LOG(("IOCTL_SET_READLINE_MODE: Invalid parameter inBuffersize:%d", inBuffersize));
				Status = STATUS_INVALID_PARAMETER;
			}
			else {
				pDevExt->LineReadMode =  ((PUCHAR)(CtrlBuff))[0];
				LOG(("IOCTL_SET_READLINE_MODE: write %d", ((PUCHAR)(CtrlBuff))[0]));
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
	LOG((__FUNCTION__));

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
	LOG((__FUNCTION__));

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
		if (!NT_SUCCESS(status)) {
			LOG(("ERROR: Unable to create device %d", NtDeviceNumber));
			return status;
		}
	}

	return status;
}

static NTSTATUS
GICParCreateDevice(
	IN PDRIVER_OBJECT pDriverObject,
	IN ULONG NtDeviceNumber
)
{
	LOG(("%s: NtDeviceNumber:%d",__FUNCTION__, NtDeviceNumber));

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
		LOG(("ERROR: Unable to create device"));
		return status;
	}

	LOG(("Created device"));

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
		LOG(("ERROR: Unable to attach to ParPort device"));
		IoDeleteDevice(pDevObj);
		pDevExts[NtDeviceNumber] = NULL;
		return status;
	}

	LOG(("Attached to ParPort device"));

	ObReferenceObjectByPointer(pDevExt->PortDeviceObject, FILE_READ_ATTRIBUTES, NULL, KernelMode);
	ObDereferenceObject(pFileObject);
	pDevExt->DeviceObject->StackSize = pDevExt->PortDeviceObject->StackSize + 1;

	// Get the port information from the port device object.
	status = GICParGetPortInfoFromPortDevice(pDevExt);
	if (!NT_SUCCESS(status))
	{
		LOG(("ERROR: Unable to get ParPort info"));
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
		LOG(("ERROR: Unable to register Symlink"));

		IoDeleteDevice(pDevObj);
		pDevExts[NtDeviceNumber] = NULL;
		return status;
	}
	LOG(("Created symlink"));

	return status;
}

static VOID
GICParDeleteDevice(
	IN PDRIVER_OBJECT pDriverObject,
	IN ULONG NtDeviceNumber
)
{
	LOG((__FUNCTION__));

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
	LOG((__FUNCTION__));

	KEVENT                      event;
	PIRP                        irp;
	PARALLEL_PORT_INFORMATION   portInfo;
	PARALLEL_PNP_INFORMATION	pnpInfo;
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
		LOG(("ERROR: Unable to create IOCTL_INTERNAL_GET_PARALLEL_PORT_INFO IoControlRequest"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = IoCallDriver(pDevExt->PortDeviceObject, irp);
	if (!NT_SUCCESS(status))
	{
		LOG(("ERROR: Unable to call IOCTL_INTERNAL_GET_PARALLEL_PORT_INFO"));
		return status;
	}

	status = KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
	if (!NT_SUCCESS(status))
	{
		LOG(("ERROR: Unable to wait for IOCTL_INTERNAL_GET_PARALLEL_PORT_INFO"));
		return status;
	}

	/////////////////////////////////////////////////////////////////////////
	// Get parallel PNP port information
	KeInitializeEvent(&event, NotificationEvent, FALSE);
	irp = IoBuildDeviceIoControlRequest(
		IOCTL_INTERNAL_GET_PARALLEL_PNP_INFO,
		pDevExt->PortDeviceObject,
		NULL, 0, &pnpInfo,
		sizeof(PARALLEL_PNP_INFORMATION),
		TRUE, &event, &ioStatus);
	if (!irp)
	{
		LOG(("ERROR: Unable to create IOCTL_INTERNAL_GET_PARALLEL_PNP_INFO IoControlRequest"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = IoCallDriver(pDevExt->PortDeviceObject, irp);
	if (!NT_SUCCESS(status))
	{
		LOG(("ERROR: Unable to call IOCTL_INTERNAL_GET_PARALLEL_PNP_INFO"));
		return status;
	}

	status = KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
	if (!NT_SUCCESS(status))
	{
		LOG(("ERROR: Unable to wait for IOCTL_INTERNAL_GET_PARALLEL_PNP_INFO"));
		return status;
	}

	// Store SPP mode info
	pDevExt->OriginalController = portInfo.OriginalController;
	pDevExt->Controller = portInfo.Controller;
	pDevExt->SpanOfController = portInfo.SpanOfController;
	pDevExt->FreePort = portInfo.FreePort;
	pDevExt->TryAllocatePort = portInfo.TryAllocatePort;
	pDevExt->PortContext = portInfo.Context;

	// Store ECP mode info
	pDevExt->OriginalEcpController = pnpInfo.OriginalEcpController;
	pDevExt->EcpController = pnpInfo.EcpController;
	pDevExt->SpanOfEcpController = pnpInfo.SpanOfEcpController;
	pDevExt->EppControllerPhysicalAddress = pnpInfo.EppControllerPhysicalAddress;
	pDevExt->SpanOfEppController = pnpInfo.SpanOfEppController;
	pDevExt->HardwareCapabilities = pnpInfo.HardwareCapabilities; // PPT_BYTE_PRESENT, PPT_ECP_PRESENT, PPT_EPP_32_PRESENT, PPT_EPP_PRESENT, PT_NO_HARDWARE_PRESENT
	pDevExt->TrySetChipMode = pnpInfo.TrySetChipMode;		// Callback to set chip mode
	pDevExt->ClearChipMode = pnpInfo.ClearChipMode;		// Callback to clear chip mode
	pDevExt->PnPContext = pnpInfo.Context;
	pDevExt->CurrentMode = (UCHAR)pnpInfo.CurrentMode;

	LOG(("OriginalController: 0x%08x",pDevExt->OriginalController.LowPart));
	LOG(("Controller: 0x%08x",(int)(UINT64)pDevExt->Controller));
	LOG(("SpanOfController: %d", (int)pDevExt->SpanOfController));
	LOG(("FreePort: 0x%08x",(int)(UINT64)pDevExt->FreePort));
	LOG(("TryAllocatePort: 0x%08x", (int)(UINT64)pDevExt->TryAllocatePort));
	LOG(("PortContext: 0x%08x", (int)(UINT64)pDevExt->PortContext));
	LOG(("OriginalEcpController: 0x%08x",pDevExt->OriginalEcpController.LowPart));
	LOG(("EcpController: 0x%08x", (int)(UINT64)pDevExt->EcpController));
	LOG(("SpanOfEcpController: %d",pDevExt->SpanOfEcpController));
	LOG(("EppControllerPhysicalAddress: 0x%08x",pDevExt->EppControllerPhysicalAddress.LowPart));
	LOG(("SpanOfEppController: %d",pDevExt->SpanOfEppController));
	LOG(("HardwareCapabilities: 0x%08x",pDevExt->HardwareCapabilities));
	LOG(("TrySetChipMode: 0x%08x", (int)(UINT64)pDevExt->TrySetChipMode));
	LOG(("ClearChipMode: 0x%08x", (int)(UINT64)pDevExt->ClearChipMode));
	LOG(("PnPContext: 0x%08x", (int)(UINT64)pDevExt->PnPContext));
	LOG(("CurrentMode: 0x%08x",pDevExt->CurrentMode));

	// Check register span
	if (pDevExt->SpanOfController < GICPAR_REGISTER_SPAN)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	return STATUS_SUCCESS;
}