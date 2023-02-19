
// MiniDebuggerDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "MiniDebugger.h"
#include "MiniDebuggerDlg.h"
#include "afxdialogex.h"

#include <tlhelp32.h>
#include <psapi.h>
#include <winioctl.h>

#include <string>

#include "DebuggerThread.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// CMiniDebuggerDlg 对话框



CMiniDebuggerDlg::CMiniDebuggerDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_MINIDEBUGGER_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMiniDebuggerDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_PROCESS, m_list_process);
	DDX_Control(pDX, IDC_EDIT1, m_edit_event);
}

BEGIN_MESSAGE_MAP(CMiniDebuggerDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_NOTIFY(NM_RCLICK, IDC_LIST_PROCESS, &CMiniDebuggerDlg::OnNMRClickListProcess)
	ON_BN_CLICKED(IDC_BUTTON1, &CMiniDebuggerDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CMiniDebuggerDlg::OnBnClickedButton2)
END_MESSAGE_MAP()


// CMiniDebuggerDlg 消息处理程序

BOOL CMiniDebuggerDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	InitProcessList();

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CMiniDebuggerDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

void CMiniDebuggerDlg::InitProcessList()
{
	//LONG lStyle;
	//lStyle = GetWindowLong(m_process_list.m_hWnd, GWL_STYLE);//获取当前窗口style
	//lStyle &= ~LVS_TYPEMASK; //清除显示方式位
	//lStyle |= LVS_REPORT; //设置style
	//lStyle |= LVS_SINGLESEL;//单选模式
	//SetWindowLong(m_process_list.m_hWnd, GWL_STYLE, lStyle);//设置style

	m_list_process.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	m_list_process.InsertColumn(0, L"进程ID", LVCFMT_LEFT, -1, 0);
	m_list_process.InsertColumn(1, L"进程名", LVCFMT_LEFT, -1, 1);
	m_list_process.SetColumnWidth(0, 50);
	m_list_process.SetColumnWidth(1, 110);


	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		MessageBox(L"CreateToolhelp32Snapshot调用失败!\n");
		return;
	}
	//遍历进程快照。轮流显示每个进程的信息
	CString strPrcNameID;
	BOOL bMore = ::Process32First(hProcessSnap, &pe32);
	int i = 0;
	while (bMore)
	{
		m_list_process.InsertItem(i, std::to_wstring(pe32.th32ProcessID).c_str());
		m_list_process.SetItemText(i, 1, pe32.szExeFile);

		bMore = Process32Next(hProcessSnap, &pe32);
		i++;
	}
	//清除snapshot对象
	CloseHandle(hProcessSnap);
}


DWORD CMiniDebuggerDlg::GetDebuggerPid()
{
	int row = m_list_process.GetSelectionMark();
	if (row < 0)
	{
		MessageBox(L"请选择调试进程");
		return 0;
	}
	CString cs_debugee_pid = m_list_process.GetItemText(row, 0);

	std::wstring ws_debuggee_pid = cs_debugee_pid.GetBuffer();

	DWORD debuggee_pid = std::stoul(ws_debuggee_pid);

	return debuggee_pid;
}

DWORD CMiniDebuggerDlg::HandleDebugEvent(DEBUG_EVENT &dbgEvt)
{
	std::wstring dbgMsg;

	switch (dbgEvt.dwDebugEventCode)
	{
		case CREATE_PROCESS_DEBUG_EVENT:
			dbgMsg = L"CREATE_PROCESS_DEBUG_EVENT";
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			dbgMsg = L"EXIT_PROCESS_DEBUG_EVENT";
			break;
		case EXCEPTION_DEBUG_EVENT:
			dbgMsg = L"EXCEPTION_DEBUG_EVENT";
			break;
		case CREATE_THREAD_DEBUG_EVENT:
			dbgMsg = L"CREATE_THREAD_DEBUG_EVENT";
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			dbgMsg = L"EXIT_THREAD_DEBUG_EVENT";
			break;
		case LOAD_DLL_DEBUG_EVENT:
			dbgMsg = L"LOAD_DLL_DEBUG_EVENT";
			break;
		case UNLOAD_DLL_DEBUG_EVENT:
			dbgMsg = L"UNLOAD_DLL_DEBUG_EVENT";
			break;
	}

	dbgMsg += L"\r\n";

	int nLength = m_edit_event.GetWindowTextLength();
	m_edit_event.SetSel(nLength, nLength);
	m_edit_event.ReplaceSel(dbgMsg.c_str());

	return DBG_CONTINUE;
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CMiniDebuggerDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CMiniDebuggerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CMiniDebuggerDlg::OnNMRClickListProcess(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码

	m_list_process.DeleteAllItems();
	m_list_process.DeleteColumn(1);
	m_list_process.DeleteColumn(0);

	InitProcessList();

	*pResult = 0;
}


void CMiniDebuggerDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码

	DWORD processId = GetDebuggerPid();

	DebuggerThread::start(processId, 
		[&](DEBUG_EVENT &dbgEvt) -> DWORD {
			return this->HandleDebugEvent(dbgEvt);
			//m_edit_event.SetWindowTextW(L"123");
			//return DBG_CONTINUE;
		}
	);
}


void CMiniDebuggerDlg::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码
	DWORD processId = GetDebuggerPid();

	DebuggerThread::stop(processId);
}
