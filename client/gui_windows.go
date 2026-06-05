package client

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
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

	IDC_RADIO_SERVER    = 1001
	IDC_RADIO_CLIENT    = 1002
	IDC_BUTTON_START    = 1003
	IDC_BUTTON_COPY     = 1004
	IDC_CHECK_ADVANCED  = 1005
	IDC_BUTTON_STOP     = 1006
	IDC_BUTTON_CHOOSE   = 1007
	IDC_BUTTON_IP_COPY  = 1008
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

type OPENFILENAMEW struct {
	LStructSize       uint32
	HWndOwner         syscall.Handle
	HInstance         syscall.Handle
	LpszFilter        *uint16
	LpszCustomFilter  *uint16
	NMaxCustFilter    uint32
	NFilterIndex      uint32
	LpszFile          *uint16
	NMaxFile          uint32
	LpszFileTitle     *uint16
	NMaxFileTitle     uint32
	LpszInitialDir    *uint16
	LpszTitle         *uint16
	Flags             uint32
	NFileOffset       uint16
	NFileExtension    uint16
	LpszDefExt        *uint16
	LCustData         uintptr
	LpfnHook          uintptr
	LpszTemplateName  *uint16
	PvReserved        unsafe.Pointer
	DwReserved        uint32
	DwFlagsEx         uint32
}

var (
	hMainWindow    syscall.Handle
	hLogBox        syscall.Handle
	hButtonStart   syscall.Handle
	hButtonStop    syscall.Handle
	hRadioServer   syscall.Handle
	hRadioClient   syscall.Handle
	hDomainLabel   syscall.Handle
	hDomainEdit    syscall.Handle
	hButtonCopy    syscall.Handle
	hInputLabel    syscall.Handle
	hInputEdit     syscall.Handle
	hCheckAdvanced syscall.Handle
	hButtonChoose  syscall.Handle
	hExePathEdit   syscall.Handle

	// 控制端连接成功后的组网 IP 专属提示组件
	hIpLabel   syscall.Handle
	hIpEdit    syscall.Handle
	hIpCopyBtn syscall.Handle

	isRunning    bool
	isServerMode = true
	showAllLogs  = false
	runFunc      func()

	// 补全导入后，这两个类型在 Windows 交叉编译时将完美通过校验
	ActiveListeners   []net.Listener
	ActivePacketConns []net.PacketConn

	associatedExePath string
	associatedCmd     *exec.Cmd
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

func CopyToClipboard(text string) {
	utf16 := textToUTF16(text)
	textLen := len(text)
	user32.NewProc("OpenClipboard").Call(0)
	user32.NewProc("EmptyClipboard").Call()
	hMem, _, _ := kernel32.NewProc("GlobalAlloc").Call(0x0002, uintptr(textLen*2+2)) // GMEM_MOVEABLE
	ptr, _, _ := kernel32.NewProc("GlobalLock").Call(hMem)

	destSlice := unsafe.Slice((*uint16)(unsafe.Pointer(ptr)), textLen+1)
	srcSlice := unsafe.Slice(utf16, textLen+1)
	copy(destSlice, srcSlice)

	kernel32.NewProc("GlobalUnlock").Call(hMem)
	user32.NewProc("SetClipboardData").Call(13, hMem) // CF_UNICODETEXT
	user32.NewProc("CloseClipboard").Call()
}

func OpenExeFileDialog(hWnd syscall.Handle) string {
	comdlg32 := syscall.NewLazyDLL("comdlg32.dll")
	procGetOpenFileName := comdlg32.NewProc("GetOpenFileNameW")

	fileBuf := make([]uint16, 260)
	filter := textToUTF16("可执行文件 (*.exe)\x00*.exe\x00所有文件 (*.*)\x00*.*\x00\x00")

	ofn := OPENFILENAMEW{
		HWndOwner:  hWnd,
		LpszFilter: filter,
		LpszFile:   &fileBuf[0],
		NMaxFile:   260,
		Flags:      0x00080000 | 0x00001000 | 0x00000800,
	}
	ofn.LStructSize = uint32(unsafe.Sizeof(ofn))

	ret, _, _ := procGetOpenFileName.Call(uintptr(unsafe.Pointer(&ofn)))
	if ret != 0 {
		return syscall.UTF16ToString(fileBuf)
	}
	return ""
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
			"token":        "quick",
			"edge-ips":     []string{"198.41.192.77:7844", "198.41.197.78:7844"},
			"ha-conn":      4,
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

func startAssociatedApp() {
	if associatedExePath != "" && associatedCmd == nil {
		log.Infoln("[System] Launching associated app (Silent Background): %s", associatedExePath)
		associatedCmd = exec.Command(associatedExePath)
		associatedCmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow: true,
		}
		err := associatedCmd.Start()
		if err != nil {
			log.Errorln("[System] Failed to start associated app: %v", err)
		} else {
			log.Infoln("[System] Associated app started successfully (PID: %d).", associatedCmd.Process.Pid)
		}
	}
}

func stopAssociatedApp() {
	if associatedCmd != nil && associatedCmd.Process != nil {
		log.Infoln("[System] Terminating associated app (PID: %d)...", associatedCmd.Process.Pid)
		_ = associatedCmd.Process.Kill()
		associatedCmd = nil
	}
}

func wndProc(hWnd syscall.Handle, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case 0x0138, 0x0133: // WM_CTLCOLORSTATIC, WM_CTLCOLOREDIT
		if lParam == uintptr(hIpEdit) {
			gdi32.NewProc("SetTextColor").Call(wParam, 0x000000FF) // RGB(255, 0, 0)
			gdi32.NewProc("SetBkMode").Call(wParam, 1)             // TRANSPARENT
			ret, _, _ := user32.NewProc("GetSysColorBrush").Call(5) // COLOR_WINDOW
			return ret
		}
	case WM_COMMAND:
		switch wParam {
		case IDC_RADIO_SERVER:
			isServerMode = true
			procShowWindow.Call(uintptr(hDomainLabel), 5) // SW_SHOW
			procShowWindow.Call(uintptr(hDomainEdit), 5)
			procShowWindow.Call(uintptr(hButtonCopy), 5)
			procShowWindow.Call(uintptr(hInputLabel), 0) // SW_HIDE
			procShowWindow.Call(uintptr(hInputEdit), 0)
			procShowWindow.Call(uintptr(hIpLabel), 0)
			procShowWindow.Call(uintptr(hIpEdit), 0)
			procShowWindow.Call(uintptr(hIpCopyBtn), 0)
			procSetWindowText.Call(uintptr(hButtonStart), uintptr(unsafe.Pointer(textToUTF16("开启被控端 (生成临时隧道)"))))
		case IDC_RADIO_CLIENT:
			isServerMode = false
			procShowWindow.Call(uintptr(hDomainLabel), 0) // SW_HIDE
			procShowWindow.Call(uintptr(hDomainEdit), 0)
			procShowWindow.Call(uintptr(hButtonCopy), 0)
			procShowWindow.Call(uintptr(hInputLabel), 5) // SW_SHOW
			procShowWindow.Call(uintptr(hInputEdit), 5)
			procShowWindow.Call(uintptr(hIpLabel), 5)
			procShowWindow.Call(uintptr(hIpEdit), 5)
			procShowWindow.Call(uintptr(hIpCopyBtn), 5)
			procSetWindowText.Call(uintptr(hButtonStart), uintptr(unsafe.Pointer(textToUTF16("一键连接被控端 (TUN虚拟网卡模式)"))))
		case IDC_BUTTON_CHOOSE:
			path := OpenExeFileDialog(hWnd)
			if path != "" {
				associatedExePath = path
				procSetWindowText.Call(uintptr(hExePathEdit), uintptr(unsafe.Pointer(textToUTF16(path))))
				log.Infoln("[System] Associated executable set to: %s", path)
			}
		case IDC_BUTTON_COPY:
			domain := getControlText(hDomainEdit)
			if domain != "" {
				CopyToClipboard(domain)
				log.Infoln("[GUI] 临时隧道域名已成功复制到系统剪贴板。")
			}
		case IDC_BUTTON_IP_COPY:
			CopyToClipboard("198.18.0.100")
			log.Infoln("[GUI] 组网专用 IP 198.18.0.100 已成功复制。请直接作为伙伴 ID 填入 TeamViewer 连接。")
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
				procSetWindowText.Call(uintptr(hButtonStart), uintptr(unsafe.Pointer(textToUTF16("正在建立连接..."))))
				user32.NewProc("EnableWindow").Call(uintptr(hRadioServer), 0)
				user32.NewProc("EnableWindow").Call(uintptr(hRadioClient), 0)
				user32.NewProc("EnableWindow").Call(uintptr(hInputEdit), 0)
				user32.NewProc("EnableWindow").Call(uintptr(hButtonStart), 0)
				user32.NewProc("EnableWindow").Call(uintptr(hButtonChoose), 0)
				user32.NewProc("EnableWindow").Call(uintptr(hButtonStop), 1)
				go runFunc()
			}
		case IDC_BUTTON_STOP:
			if isRunning {
				log.Infoln("[System] Closing tunnel and releasing system network resources...")
				isRunning = false

				for _, l := range ActiveListeners {
					_ = l.Close()
				}
				ActiveListeners = nil
				for _, pc := range ActivePacketConns {
					_ = pc.Close()
				}
				ActivePacketConns = nil

				DeleteTunDevice("cftun0")
				stopAssociatedApp()

				procSetWindowText.Call(uintptr(hButtonStart), uintptr(unsafe.Pointer(textToUTF16("一键激活加速隧道"))))
				user32.NewProc("EnableWindow").Call(uintptr(hRadioServer), 1)
				user32.NewProc("EnableWindow").Call(uintptr(hRadioClient), 1)
				user32.NewProc("EnableWindow").Call(uintptr(hInputEdit), 1)
				user32.NewProc("EnableWindow").Call(uintptr(hButtonStart), 1)
				user32.NewProc("EnableWindow").Call(uintptr(hButtonChoose), 1)
				user32.NewProc("EnableWindow").Call(uintptr(hButtonStop), 0)

				log.Infoln("[System] Engine stopped successfully. Ready for next connection.")
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
		stopAssociatedApp()
		DeleteTunDevice("cftun0")
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

		if strings.Contains(cleanText, "[Tunnel] Connected successfully") || strings.Contains(cleanText, "[STACK] tun://") {
			go startAssociatedApp()
		}

		utf16Text := textToUTF16(cleanText + "\r\n")
		user32.NewProc("SendMessageW").Call(uintptr(hLogBox), EM_SETSEL, uintptr(0xFFFFFFFF), uintptr(0xFFFFFFFF))
		user32.NewProc("SendMessageW").Call(uintptr(hLogBox), EM_REPLACESEL, uintptr(0), uintptr(unsafe.Pointer(utf16Text)))
	}
}

func CheckSingleInstance() bool {
	hOld, _, _ := procFindWindow.Call(uintptr(unsafe.Pointer(textToUTF16("CFTUN_GUI_CLASS"))), 0)
	if hOld != 0 {
		procShowWindow.Call(hOld, 9)
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
		HbrBackground: syscall.Handle(5),
		LpszClassName: className,
	}
	wc.CbSize = uint32(unsafe.Sizeof(wc))
	
	// 核心修复：添加 uintptr 显式强转，确保 32/64 位编译器在所有平台下通过语法校验
	procRegisterClass.Call(uintptr(unsafe.Pointer(&wc)))

	hMainVal, _, _ := procCreateWindow.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(textToUTF16("CFTUN 远程桌面专属加速控制面板"))),
		WS_OVERLAPPEDWINDOW|WS_VISIBLE,
		100, 100, 680, 640,
		0, 0, hInstance, 0,
	)
	hMainWindow = syscall.Handle(hMainVal)

	hFontNormal, _, _ := gdi32.NewProc("CreateFontW").Call(
		18, 0, 0, 0, 400, 0, 0, 0,
		1, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(textToUTF16("Microsoft YaHei"))),
	)
	hFontBold, _, _ := gdi32.NewProc("CreateFontW").Call(
		22, 0, 0, 0, 700, 0, 0, 0,
		1, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(textToUTF16("Microsoft YaHei"))),
	)
	hFontLog, _, _ := gdi32.NewProc("CreateFontW").Call(
		16, 0, 0, 0, 400, 0, 0, 0,
		1, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(textToUTF16("Microsoft YaHei"))),
	)

	// 1. 加速模式选择
	hGrpRoleVal, _, _ := procCreateWindow.Call(
		0, uintptr(unsafe.Pointer(textToUTF16("BUTTON"))), uintptr(unsafe.Pointer(textToUTF16("加速模式选择"))),
		WS_CHILD|WS_VISIBLE|0x0007, 10, 10, 644, 75, hMainVal, 0, hInstance, 0,
	)
	hGrpRole := syscall.Handle(hGrpRoleVal)

	hRadioServerVal, _, _ := procCreateWindow.Call(
		0, uintptr(unsafe.Pointer(textToUTF16("BUTTON"))), uintptr(unsafe.Pointer(textToUTF16("我是被控端 (服务端)"))),
		WS_CHILD|WS_VISIBLE|0x0009, 25, 32, 220, 35, hMainVal, IDC_RADIO_SERVER, hInstance, 0,
	)
	hRadioServer = syscall.Handle(hRadioServerVal)

	hRadioClientVal, _, _ := procCreateWindow.Call(
		0, uintptr(unsafe.Pointer(textToUTF16("BUTTON"))), uintptr(unsafe.Pointer(textToUTF16("我是控制端 (客户端-网卡模式)"))),
		WS_CHILD|WS_VISIBLE|0x0009, 260, 32, 360, 35, hMainVal, IDC_RADIO_CLIENT, hInstance, 0,
	)
	hRadioClient = syscall.Handle(hRadioClientVal)

	// 2. 被控端域名看板
	hDomainLabelVal, _, _ := procCreateWindow.Call(
		0, uintptr(unsafe.Pointer(textToUTF16("STATIC"))), uintptr(unsafe.Pointer(textToUTF16("您的临时加速域名 (一键复制)："))),
		WS_CHILD|WS_VISIBLE, 15, 100, 250, 30, hMainVal, 0, hInstance, 0,
	)
	hDomainLabel = syscall.Handle(hDomainLabelVal)

	hDomainEditVal, _, _ := procCreateWindow.Call(
		0x00000200, uintptr(unsafe.Pointer(textToUTF16("EDIT"))), 0,
		WS_CHILD|WS_VISIBLE|0x0800, 270, 96, 260, 35, hMainVal, 0, hInstance, 0,
	)
	hDomainEdit = syscall.Handle(hDomainEditVal)

	hButtonCopyVal, _, _ := procCreateWindow.Call(
		0, uintptr(unsafe.Pointer(textToUTF16("BUTTON"))), uintptr(unsafe.Pointer(textToUTF16("复制域名"))),
		WS_CHILD|WS_VISIBLE, 540, 94, 110, 35, hMainVal, IDC_BUTTON_COPY, hInstance, 0,
	)
	hButtonCopy = syscall.Handle(hButtonCopyVal)

	// 3. 控制端域名输入组件 (默认隐藏)
	hInputLabelVal, _, _ := procCreateWindow.Call(
		0, uintptr(unsafe.Pointer(textToUTF16("STATIC"))), uintptr(unsafe.Pointer(textToUTF16("请输入被控端的临时域名："))),
		WS_CHILD, 15, 100, 250, 30, hMainVal, 0, hInstance, 0,
	)
	hInputLabel = syscall.Handle(hInputLabelVal)

	hInputEditVal, _, _ := procCreateWindow.Call(
		0x00000200, uintptr(unsafe.Pointer(textToUTF16("EDIT"))), 0,
		WS_CHILD|0x0080, 270, 96, 380, 35, hMainVal, 0, hInstance, 0,
	)
	hInputEdit = syscall.Handle(hInputEditVal)

	// 4. 核心升级：控制端连接后的专属组网红字 IP 提醒
	hIpLabelVal, _, _ := procCreateWindow.Call(
		0, uintptr(unsafe.Pointer(textToUTF16("STATIC"))), uintptr(unsafe.Pointer(textToUTF16("远程控制专属目标组网 IP："))),
		WS_CHILD, 15, 145, 250, 30, hMainVal, 0, hInstance, 0,
	)
	hIpLabel = syscall.Handle(hIpLabelVal)

	hIpEditVal, _, _ := procCreateWindow.Call(
		0x00000200, uintptr(unsafe.Pointer(textToUTF16("EDIT"))), uintptr(unsafe.Pointer(textToUTF16("198.18.0.100"))),
		WS_CHILD|0x0800, 270, 141, 260, 35, hMainVal, 0, hInstance, 0,
	)
	hIpEdit = syscall.Handle(hIpEditVal)

	hIpCopyBtnVal, _, _ := procCreateWindow.Call(
		0, uintptr(unsafe.Pointer(textToUTF16("BUTTON"))), uintptr(unsafe.Pointer(textToUTF16("复制 IP"))),
		WS_CHILD, 540, 139, 110, 35, hMainVal, IDC_BUTTON_IP_COPY, hInstance, 0,
	)
	hIpCopyBtn = syscall.Handle(hIpCopyBtnVal)

	// 5. 关联启动 EXE 选择组件
	hButtonChooseVal, _, _ := procCreateWindow.Call(
		0, uintptr(unsafe.Pointer(textToUTF16("BUTTON"))), uintptr(unsafe.Pointer(textToUTF16("选择要关联启动的软件 (.exe)"))),
		WS_CHILD|WS_VISIBLE, 10, 190, 280, 40, hMainVal, IDC_BUTTON_CHOOSE, hInstance, 0,
	)
	hButtonChoose = syscall.Handle(hButtonChooseVal)

	hExePathEditVal, _, _ := procCreateWindow.Call(
		0x00000200, uintptr(unsafe.Pointer(textToUTF16("EDIT"))), 0,
		WS_CHILD|WS_VISIBLE|0x0800, 300, 192, 350, 35, hMainVal, 0, hInstance, 0,
	)
	hExePathEdit = syscall.Handle(hExePathEditVal)

	// 6. 控制按钮组：一键开启 与 停止
	hButtonStartVal, _, _ := procCreateWindow.Call(
		0, uintptr(unsafe.Pointer(textToUTF16("BUTTON"))), uintptr(unsafe.Pointer(textToUTF16("一键开启加速"))),
		WS_CHILD|WS_VISIBLE, 10, 245, 310, 65, hMainVal, IDC_BUTTON_START, hInstance, 0,
	)
	hButtonStart = syscall.Handle(hButtonStartVal)

	hButtonStopVal, _, _ := procCreateWindow.Call(
		0, uintptr(unsafe.Pointer(textToUTF16("BUTTON"))), uintptr(unsafe.Pointer(textToUTF16("停止加速"))),
		WS_CHILD|WS_VISIBLE, 340, 245, 310, 65, hMainVal, IDC_BUTTON_STOP, hInstance, 0,
	)
	hButtonStop = syscall.Handle(hButtonStopVal)
	user32.NewProc("EnableWindow").Call(uintptr(hButtonStop), 0)

	hCheckAdvancedVal, _, _ := procCreateWindow.Call(
		0, uintptr(unsafe.Pointer(textToUTF16("BUTTON"))), uintptr(unsafe.Pointer(textToUTF16("高级设置：显示底层全量 Debug 日志"))),
		WS_CHILD|WS_VISIBLE|0x0003, 10, 320, 450, 30, hMainVal, IDC_CHECK_ADVANCED, hInstance, 0,
	)
	hCheckAdvanced = syscall.Handle(hCheckAdvancedVal)

	// 7. 日志监视编辑框
	hLogBoxVal, _, _ := procCreateWindow.Call(
		0x00000200, uintptr(unsafe.Pointer(textToUTF16("EDIT"))), 0,
		WS_CHILD|WS_VISIBLE|ES_MULTILINE|ES_AUTOVSCROLL|WS_VSCROLL|0x0800,
		10, 355, 644, 230, hMainVal, 0, hInstance, 0,
	)
	hLogBox = syscall.Handle(hLogBoxVal)

	// 默认勾选被控端 Radio
	user32.NewProc("SendMessageW").Call(uintptr(hRadioServer), BM_SETCHECK, 1, 0)

	// 应用“微软雅黑-普通大号”字体
	allNormalControls := []syscall.Handle{hGrpRole, hRadioServer, hRadioClient, hDomainLabel, hInputLabel, hIpLabel, hCheckAdvanced, hButtonChoose, hExePathEdit}
	for _, ctrl := range allNormalControls {
		user32.NewProc("SendMessageW").Call(uintptr(ctrl), 0x0030, uintptr(hFontNormal), 1)
	}

	// 应用“微软雅黑-加粗大号”字体
	allBoldControls := []syscall.Handle{hDomainEdit, hButtonCopy, hInputEdit, hIpEdit, hIpCopyBtn, hButtonStart, hButtonStop}
	for _, ctrl := range allBoldControls {
		user32.NewProc("SendMessageW").Call(uintptr(ctrl), 0x0030, uintptr(hFontBold), 1)
	}

	// 日志终端应用16号等高线字体
	user32.NewProc("SendMessageW").Call(uintptr(hLogBox), 0x0030, uintptr(hFontLog), 1)

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
