package client

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/fmnx/cftun/log"
)

var (
	user32               = syscall.NewLazyDLL("user32.dll")
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	gdi32                = syscall.NewLazyDLL("gdi32.dll")
	procCreateWindow     = user32.NewProc("CreateWindowExW")
	procDefWindow        = user32.NewProc("DefWindowProcW")
	procRegisterClass    = user32.NewProc("RegisterClassExW")
	procGetMessage       = user32.NewProc("GetMessageW")
	procTranslateMsg     = user32.NewProc("TranslateMessage")
	procDispatchMsg      = user32.NewProc("DispatchMessageW")
	procSetWindowText    = user32.NewProc("SetWindowTextW")
	procShowWindow       = user32.NewProc("ShowWindow")
	procSetForeground    = user32.NewProc("SetForegroundWindow")
	procFindWindow       = user32.NewProc("FindWindowW")
	procGetWindowText    = user32.NewProc("GetWindowTextW")
	procGetWindowTextLen = user32.NewProc("GetWindowTextLengthW")
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
	BM_SETCHECK         = 0x00F1
	BM_GETCHECK         = 0x00F0

	EM_SETSEL     = 0x00B1
	EM_REPLACESEL = 0x00C2

	IDC_RADIO_SERVER   = 1001
	IDC_RADIO_CLIENT   = 1002
	IDC_BUTTON_START   = 1003
	IDC_BUTTON_COPY    = 1004
	IDC_CHECK_ADVANCED = 1005
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
	hMainWindow   syscall.Handle
	hLogBox       syscall.Handle
	hButtonStart  syscall.Handle
	hRadioServer  syscall.Handle
	hRadioClient  syscall.Handle
	hDomainLabel  syscall.Handle
	hDomainEdit   syscall.Handle
	hButtonCopy   syscall.Handle
	hInputLabel   syscall.Handle
	hInputEdit    syscall.Handle
	hCheckAdvanced syscall.Handle

	isRunning    bool
	isServerMode = true
	showAllLogs  = false
	runFunc      func()
)

func textToUTF16(s string) *uint16 {
	val, _ := syscall.UTF16PtrFromString(s)
	return val
}

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
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				inEscape = false
			}
			continue
		}
		buf = append(buf, r)
	}
	return string(buf)
}

// CopyToClipboard 原生 Windows 无 CGO 剪贴板复制引擎
func CopyToClipboard(text string) {
	utf16 := textToUTF16(text)
	textLen := len(text)
	user32.NewProc("OpenClipboard").Call(0)
	user32.NewProc("EmptyClipboard").Call()
	hMem, _, _ := kernel32.NewProc("GlobalAlloc").Call(0x0002, uintptr(textLen*2+2)) // GMEM_MOVEABLE
	ptr, _, _ := kernel32.NewProc("GlobalLock").Call(hMem)
	
	// 核心修复：采用 Go 1.17+ 原生的切片转换进行无损、安全的底层 C-指针内存拷贝
	destSlice := unsafe.Slice((*uint16)(unsafe.Pointer(ptr)), textLen+1)
	srcSlice := unsafe.Slice(utf16, textLen+1)
	copy(destSlice, srcSlice)
	
	kernel32.NewProc("GlobalUnlock").Call(hMem)
	user32.NewProc("SetClipboardData").Call(13, hMem) // CF_UNICODETEXT
	user32.NewProc("CloseClipboard").Call()
}

func getControlText(hEdit syscall.Handle) string {
	lenVal, _, _ := procGetWindowTextLen.Call(uintptr(hEdit))
	if lenVal == 0 {
		return ""
	}
	buf := make([]uint16, lenVal+1)
	procGetWindowText.Call(uintptr(hEdit), uintptr(unsafe.Pointer(&buf[0])), lenVal+1)
	return syscall.UTF16ToString(buf)
}

func writeDefaultServerConfig() {
	configMap := map[string]interface{}{
		"server": map[string]interface{}{
			"token":    "quick",
			"edge-ips": []string{"198.41.192.77:7844", "198.41.197.78:7844"},
			"ha-conn":  4,
			"bind-address": "",
		},
	}
	data, _ := json.MarshalIndent(configMap, "", "  ")
	_ = os.WriteFile("config.json", data, 0644)
}

func writeClientConfig(targetDomain string) {
	configMap := map[string]interface{}{
		"client": map[string]interface{}{
			"cdn-ip":     "auto",
			"cdn-port":   443,
			"scheme":     "wss",
			"global-url": strings.TrimSpace(targetDomain),
			"tun": map[string]interface{}{
				"enable":    true,
				"name":      "cftun0",
				"log-level": "info",
				"routes":    []string{"198.18.0.100/32"},
			},
		},
	}
	data, _ := json.MarshalIndent(configMap, "", "  ")
	_ = os.WriteFile("config.json", data, 0644)
}

func wndProc(hWnd syscall.Handle, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case WM_COMMAND:
		switch wParam {
		case IDC_RADIO_SERVER:
			isServerMode = true
			procShowWindow.Call(uintptr(hDomainLabel), 5) // SW_SHOW
			procShowWindow.Call(uintptr(hDomainEdit), 5)
			procShowWindow.Call(uintptr(hButtonCopy), 5)
			procShowWindow.Call(uintptr(hInputLabel), 0) // SW_HIDE
			procShowWindow.Call(uintptr(hInputEdit), 0)
			procSetWindowText.Call(uintptr(hButtonStart), uintptr(unsafe.Pointer(textToUTF16("开启被控端 (生成临时隧道)"))))
		case IDC_RADIO_CLIENT:
			isServerMode = false
			procShowWindow.Call(uintptr(hDomainLabel), 0) // SW_HIDE
			procShowWindow.Call(uintptr(hDomainEdit), 0)
			procShowWindow.Call(uintptr(hButtonCopy), 0)
			procShowWindow.Call(uintptr(hInputLabel), 5) // SW_SHOW
			procShowWindow.Call(uintptr(hInputEdit), 5)
			procSetWindowText.Call(uintptr(hButtonStart), uintptr(unsafe.Pointer(textToUTF16("一键连接被控端 (TUN虚拟网卡模式)"))))
		case IDC_BUTTON_COPY:
			domain := getControlText(hDomainEdit)
			if domain != "" {
				CopyToClipboard(domain)
				log.Infoln("[GUI] 临时隧道域名已成功复制到系统剪贴板。")
			}
		case IDC_BUTTON_START:
			if !isRunning {
				if isServerMode {
					writeDefaultServerConfig()
				} else {
					domain := getControlText(hInputEdit)
					if domain == "" {
						WriteLogToGui("[GUI] 错误：请输入被控端提供的临时隧道域名！")
						return 0
					}
					writeClientConfig(domain)
				}
				isRunning = true
				procSetWindowText.Call(uintptr(hButtonStart), uintptr(unsafe.Pointer(textToUTF16("加速引擎工作中..."))))
				user32.NewProc("EnableWindow").Call(uintptr(hRadioServer), 0)
				user32.NewProc("EnableWindow").Call(uintptr(hRadioClient), 0)
				user32.NewProc("EnableWindow").Call(uintptr(hInputEdit), 0)
				user32.NewProc("EnableWindow").Call(uintptr(hButtonStart), 0)
				go runFunc()
			}
		case IDC_CHECK_ADVANCED:
			checkState, _, _ := user32.NewProc("SendMessageW").Call(uintptr(hCheckAdvanced), BM_GETCHECK, 0, 0)
			if checkState == 1 {
				showAllLogs = true
				log.Infoln("[GUI] 调试级(Debug)全量日志已开启。")
			} else {
				showAllLogs = false
				log.Infoln("[GUI] 调试级(Debug)日志已屏蔽，仅输出主要就绪日志。")
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

func WriteLogToGui(text string) {
	if hLogBox != 0 {
		cleanText := stripANSI(text)

		if !showAllLogs && strings.Contains(cleanText, "[DEBUG]") {
			return
		}

		if strings.Contains(cleanText, "THE TEMPORARY DOMAIN YOU HAVE APPLIED FOR IS:") {
			parts := strings.Split(cleanText, "IS: ")
			if len(parts) > 1 {
				domain := strings.TrimSpace(parts[1])
				procSetWindowText.Call(uintptr(hDomainEdit), uintptr(unsafe.Pointer(textToUTF16(domain))))
			}
		}

		utf16Text := textToUTF16(cleanText + "\r\n")
		user32.NewProc("SendMessageW").Call(uintptr(hLogBox), EM_SETSEL, uintptr(0xFFFFFFFF), uintptr(0xFFFFFFFF))
		user32.NewProc("SendMessageW").Call(uintptr(hLogBox), EM_REPLACESEL, uintptr(0), uintptr(unsafe.Pointer(utf16Text)))
	}
}

func CheckSingleInstance() bool {
	hOld, _, _ := procFindWindow.Call(uintptr(unsafe.Pointer(textToUTF16("CFTUN_GUI_CLASS"))), 0)
	if hOld != 0 {
		procShowWindow.Call(hOld, 9) // SW_RESTORE
		procSetForeground.Call(hOld)
		return true
	}
	return false
}

func StartWindowsGUI(onStart func()) {
	if CheckSingleInstance() {
		syscall.ExitProcess(0)
	}

	runtime.LockOSThread()
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

	hMainVal, _, _ := procCreateWindow.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(textToUTF16("CFTUN 远程桌面专属加速控制面板"))),
		WS_OVERLAPPEDWINDOW|WS_VISIBLE,
		100, 100, 620, 520,
		0, 0, hInstance, 0,
	)
	hMainWindow = syscall.Handle(hMainVal)

	hFont, _, _ := gdi32.NewProc("CreateFontW").Call(
		15, 0, 0, 0, 400, 0, 0, 0,
		1, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(textToUTF16("Microsoft YaHei"))),
	)

	// 1. 创建角色单选框
	hGrpRoleVal, _, _ := procCreateWindow.Call(
		0, uintptr(unsafe.Pointer(textToUTF16("BUTTON"))), uintptr(unsafe.Pointer(textToUTF16("加速模式选择"))),
		WS_CHILD|WS_VISIBLE|0x0007, 10, 10, 580, 60, hMainVal, 0, hInstance, 0, // BS_GROUPBOX
	)
	hGrpRole := syscall.Handle(hGrpRoleVal) // 核心修复：转化为统一的 Handle 避开类型校验冲突

	hRadioServerVal, _, _ := procCreateWindow.Call(
		0, uintptr(unsafe.Pointer(textToUTF16("BUTTON"))), uintptr(unsafe.Pointer(textToUTF16("我是被控端 (服务端)"))),
		WS_CHILD|WS_VISIBLE|0x0009, 25, 30, 200, 30, hMainVal, IDC_RADIO_SERVER, hInstance, 0, // BS_AUTORADIOBUTTON
	)
	hRadioServer = syscall.Handle(hRadioServerVal)

	hRadioClientVal, _, _ := procCreateWindow.Call(
		0, uintptr(unsafe.Pointer(textToUTF16("BUTTON"))), uintptr(unsafe.Pointer(textToUTF16("我是控制端 (客户端-网卡模式)"))),
		WS_CHILD|WS_VISIBLE|0x0009, 260, 30, 260, 30, hMainVal, IDC_RADIO_CLIENT, hInstance, 0,
	)
	hRadioClient = syscall.Handle(hRadioClientVal)

	// 2. 被控端域名看板组件
	hDomainLabelVal, _, _ := procCreateWindow.Call(
		0, uintptr(unsafe.Pointer(textToUTF16("STATIC"))), uintptr(unsafe.Pointer(textToUTF16("您的临时加速域名 (一键复制)："))),
		WS_CHILD|WS_VISIBLE, 15, 85, 230, 20, hMainVal, 0, hInstance, 0,
	)
	hDomainLabel = syscall.Handle(hDomainLabelVal)

	hDomainEditVal, _, _ := procCreateWindow.Call(
		0x00000200, uintptr(unsafe.Pointer(textToUTF16("EDIT"))), 0,
		WS_CHILD|WS_VISIBLE|0x0800, 240, 80, 250, 25, hMainVal, 0, hInstance, 0, // ES_READONLY
	)
	hDomainEdit = syscall.Handle(hDomainEditVal)

	hButtonCopyVal, _, _ := procCreateWindow.Call(
		0, uintptr(unsafe.Pointer(textToUTF16("BUTTON"))), uintptr(unsafe.Pointer(textToUTF16("复制域名"))),
		WS_CHILD|WS_VISIBLE, 500, 78, 90, 28, hMainVal, IDC_BUTTON_COPY, hInstance, 0,
	)
	hButtonCopy = syscall.Handle(hButtonCopyVal)

	// 3. 控制端域名输入组件 (默认隐藏)
	hInputLabelVal, _, _ := procCreateWindow.Call(
		0, uintptr(unsafe.Pointer(textToUTF16("STATIC"))), uintptr(unsafe.Pointer(textToUTF16("请输入被控端的临时域名："))),
		WS_CHILD, 15, 85, 200, 20, hMainVal, 0, hInstance, 0,
	)
	hInputLabel = syscall.Handle(hInputLabelVal)

	hInputEditVal, _, _ := procCreateWindow.Call(
		0x00000200, uintptr(unsafe.Pointer(textToUTF16("EDIT"))), 0,
		WS_CHILD|0x0080, 240, 80, 350, 25, hMainVal, 0, hInstance, 0, // ES_AUTOHSCROLL
	)
	hInputEdit = syscall.Handle(hInputEditVal)

	// 4. 控制激活大按钮与高级设置
	hButtonStartVal, _, _ := procCreateWindow.Call(
		0, uintptr(unsafe.Pointer(textToUTF16("BUTTON"))), uintptr(unsafe.Pointer(textToUTF16("开启被控端 (生成临时隧道)"))),
		WS_CHILD|WS_VISIBLE, 10, 125, 580, 50, hMainVal, IDC_BUTTON_START, hInstance, 0,
	)
	hButtonStart = syscall.Handle(hButtonStartVal)

	hCheckAdvancedVal, _, _ := procCreateWindow.Call(
		0, uintptr(unsafe.Pointer(textToUTF16("BUTTON"))), uintptr(unsafe.Pointer(textToUTF16("高级设置：显示底层全量 Debug 日志"))),
		WS_CHILD|WS_VISIBLE|0x0003, 10, 185, 300, 20, hMainVal, IDC_CHECK_ADVANCED, hInstance, 0, // BS_AUTOCHECKBOX
	)
	hCheckAdvanced = syscall.Handle(hCheckAdvancedVal)

	// 5. 日志监视编辑框
	hLogBoxVal, _, _ := procCreateWindow.Call(
		0x00000200, uintptr(unsafe.Pointer(textToUTF16("EDIT"))), 0,
		WS_CHILD|WS_VISIBLE|ES_MULTILINE|ES_AUTOVSCROLL|WS_VSCROLL|0x0800,
		10, 215, 580, 250, hMainVal, 0, hInstance, 0,
	)
	hLogBox = syscall.Handle(hLogBoxVal)

	// 默认勾选被控端 Radio
	user32.NewProc("SendMessageW").Call(uintptr(hRadioServer), BM_SETCHECK, 1, 0)

	// 全员应用“微软雅黑”美化字体
	allControls := []syscall.Handle{hGrpRole, hRadioServer, hRadioClient, hDomainLabel, hDomainEdit, hButtonCopy, hInputLabel, hInputEdit, hButtonStart, hCheckAdvanced, hLogBox}
	for _, ctrl := range allControls {
		user32.NewProc("SendMessageW").Call(uintptr(ctrl), 0x0030, uintptr(hFont), 1) // WM_SETFONT
	}

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
