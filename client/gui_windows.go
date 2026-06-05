package client

import (
	"fmt"
	"runtime"
	"strings"
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

// stripANSI 过滤清除控制台彩色字符，保障 Windows 原生组件正常换行与字符显示
func stripANSI(s string) string {
	var buf []rune
	inEscape := false
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == '\x1b' || r == '\033' {
			inEscape = true
			continue
		}
		if inEscape {
			// ANSI 终端控制序列通常以英文字母（A-Z, a-z）结束
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				inEscape = false
			}
			continue
		}
		buf = append(buf, r)
	}
	return string(buf)
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

// WriteLogToGui 追加日志并完成视觉排版微调
func WriteLogToGui(text string) {
	if hLogBox != 0 {
		cleanText := stripANSI(text)

		// 核心优化：若包含临时域名，自动生成醒目的分割边框，使其极易被寻找和一键复制
		if strings.Contains(cleanText, "THE TEMPORARY DOMAIN YOU HAVE APPLIED FOR IS:") {
			cleanText = "\r\n============================================================\r\n" +
				cleanText +
				"\r\n============================================================\r\n"
		}

		utf16Text := textToUTF16(cleanText + "\r\n")
		// 将编辑框的光标移到最后
		user32.NewProc("SendMessageW").Call(uintptr(hLogBox), EM_SETSEL, uintptr(0xFFFFFFFF), uintptr(0xFFFFFFFF))
		// 在当前光标处追加文本
		user32.NewProc("SendMessageW").Call(uintptr(hLogBox), EM_REPLACESEL, uintptr(0), uintptr(unsafe.Pointer(utf16Text)))
	}
}

func StartWindowsGUI(onStart func()) {
	runtime.LockOSThread()
	
	runFunc = onStart
	hInstance, _, _ := kernel32.NewProc("GetModuleHandleW").Call(0)

	className := textToUTF16("CFTUN_GUI_CLASS")
	wc := WNDCLASSEXW{
		Style:         0,
		LpfnWndProc:   syscall.NewCallback(wndProc),
		HInstance:     syscall.Handle(hInstance),
		HbrBackground: syscall.Handle(5),
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

	hLogBoxVal, _, _ := procCreateWindow.Call(
		0x00000200,
		uintptr(unsafe.Pointer(textToUTF16("EDIT"))),
		0,
		WS_CHILD|WS_VISIBLE|ES_MULTILINE|ES_AUTOVSCROLL|WS_VSCROLL|0x0800,
		10, 10, 580, 320,
		hMain, 0, hInstance, 0,
	)
	hLogBox = syscall.Handle(hLogBoxVal)

	// 启动控制按钮
	hButtonVal, _, _ := procCreateWindow.Call(
		0,
		uintptr(unsafe.Pointer(textToUTF16("BUTTON"))),
		uintptr(unsafe.Pointer(textToUTF16("一键激活远程桌面全链路加速"))),
		WS_CHILD|WS_VISIBLE,
		10, 350, 580, 55,
		hMain, 0, hInstance, 0,
	)
	hButton = syscall.Handle(hButtonVal)

	go func() {
		sub, err := log.Subscribe()
		if err == nil {
			for event := range sub {
				WriteLogToGui(fmt.Sprintf("[%s] %s", event.LogLevel.String(), event.Payload))
			}
		}
	}()

	log.Infoln("[GUI] Control panel loaded successfully.")

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
