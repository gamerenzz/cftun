package client

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/fmnx/cftun/log"
)

var (
	user32           = syscall.NewLazyDLL("user32.dll")
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procCreateWindow = user32.NewProc("CreateWindowExW")
	procDefWindow    = user32.NewProc("DefWindowProcW")
	procRegisterClass= user32.NewProc("RegisterClassExW")
	procGetMessage   = user32.NewProc("GetMessageW")
	procTranslateMsg = user32.NewProc("TranslateMessage")
	procDispatchMsg  = user32.NewProc("DispatchMessageW")
	procSetWindowText= user32.NewProc("SetWindowTextW")
)

const (
	WS_OVERLAPPEDWINDOW = 0x00CF0000
	WS_VISIBLE          = 0x10000000
	WS_CHILD            = 0x40000000
	ES_MULTILINE        = 0x0004
	ES_AUTOVSCROLL      = 0x0040
	WS_VSCROLL          = 0x00200000
	WM_COMMAND          = 0x0111
	WM_DESTROY          = 0x0002

	// Win32 Edit 控件追加消息，规避死锁
	EM_SETSEL     = 0x00B1
	EM_REPLACESEL = 0x00C2
)

type WNDCLASSEXW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     syscall.Handle
	HIcon         syscall.Handle
	HCursor       syscall.Handle
	HbrBackground syscall.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       syscall.Handle
}

type MSG struct {
	HWnd    syscall.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

var (
	hLogBox   syscall.Handle
	hButton   syscall.Handle
	isRunning bool
	runFunc   func()
)

func textToUTF16(s string) *uint16 {
	val, _ := syscall.UTF16PtrFromString(s)
	return val
}

func wndProc(hWnd syscall.Handle, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case WM_COMMAND:
		if lParam == uintptr(hButton) {
			if !isRunning {
				isRunning = true
				procSetWindowText.Call(uintptr(hButton), uintptr(unsafe.Pointer(textToUTF16("加速引擎工作中..."))))
				go runFunc()
			}
		}
	case WM_DESTROY:
		syscall.ExitProcess(0)
	default:
		ret, _, _ := procDefWindow.Call(uintptr(hWnd), uintptr(msg), wParam, lParam)
		return ret
	}
	return 0
}

// WriteLogToGui 采用高效、无死锁的 EM_SETSEL + EM_REPLACESEL 机制在末尾追加日志
func WriteLogToGui(text string) {
	if hLogBox != 0 {
		utf16Text := textToUTF16(text + "\r\n")
		// 将编辑框的光标移到最后
		user32.NewProc("SendMessageW").Call(uintptr(hLogBox), EM_SETSEL, uintptr(0xFFFFFFFF), uintptr(0xFFFFFFFF))
		// 在当前光标（即末尾）直接追加文本，避免读取和全选，彻底防止界面挂起
		user32.NewProc("SendMessageW").Call(uintptr(hLogBox), EM_REPLACESEL, uintptr(0), uintptr(unsafe.Pointer(utf16Text)))
	}
}

func StartWindowsGUI(onStart func()) {
	runFunc = onStart
	hInstance, _, _ := kernel32.NewProc("GetModuleHandleW").Call(0)

	className := textToUTF16("CFTUN_GUI_CLASS")
	wc := WNDCLASSEXW{
		Style:         0,
		LpfnWndProc:   syscall.NewCallback(wndProc),
		HInstance:     syscall.Handle(hInstance),
		HbrBackground: syscall.Handle(5), // COLOR_WINDOW
		LpszClassName: className,
	}
	wc.CbSize = uint32(unsafe.Sizeof(wc))
	procRegisterClass.Call(uintptr(unsafe.Pointer(&wc)))

	hMain, _, _ := procCreateWindow.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(textToUTF16("CFTUN 远程桌面专属加速控制面板"))),
		WS_OVERLAPPEDWINDOW|WS_VISIBLE,
		100, 100, 620, 480,
		0, 0, hInstance, 0,
	)

	// 控制台日志编辑框
	hLogBoxVal, _, _ := procCreateWindow.Call(
		0x00000200, // WS_EX_CLIENTEDGE
		uintptr(unsafe.Pointer(textToUTF16("EDIT"))),
		0,
		WS_CHILD|WS_VISIBLE|ES_MULTILINE|ES_AUTOVSCROLL|WS_VSCROLL|0x0800,
		10, 10, 580, 320,
		hMain, 0, hInstance, 0,
	)
	hLogBox = syscall.Handle(hLogBoxVal)

	// 启动控制按钮
	hBtnVal, _, _ := procCreateWindow.Call(
		0,
		uintptr(unsafe.Pointer(textToUTF16("BUTTON"))),
		uintptr(unsafe.Pointer(textToUTF16("一键激活远程桌面全链路加速"))),
		WS_CHILD|WS_VISIBLE,
		10, 350, 580, 55,
		hMain, 0, hInstance, 0,
	)
	hButton = syscall.Handle(hBtnVal)

	log.Infoln("[GUI] Control panel loaded successfully.")

	go func() {
		sub, err := log.Subscribe()
		if err == nil {
			for event := range sub {
				WriteLogToGui(fmt.Sprintf("[%s] %s", event.LogLevel.String(), event.Payload))
			}
		}
	}()

	var msg MSG
	for {
		ret, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if ret == 0 {
			break
		}
		procTranslateMsg.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMsg.Call(uintptr(unsafe.Pointer(&msg)))
	}
}
