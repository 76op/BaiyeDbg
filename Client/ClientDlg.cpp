
// ClientDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "Client.h"
#include "ClientDlg.h"
#include "afxdialogex.h"

#include <tlhelp32.h>
#include <psapi.h>
#include <winioctl.h>

#include "load_drv.h"
#include "kernel_msg.h"

#include <string>
#include <sstream>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CClientDlg 对话框



CClientDlg::CClientDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_CLIENT_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CClientDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_PROCESS_LIST, m_process_list);
	DDX_Control(pDX, IDC_EDIT1, m_debugger_pid);
	DDX_Control(pDX, IDC_EDIT_ALLOCATED_VM, m_allocated_vm_edit);
}

BEGIN_MESSAGE_MAP(CClientDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST_PROCESS_LIST, &CClientDlg::OnLvnItemchangedListProcessList)
	ON_BN_CLICKED(IDC_BUTTON_LOAD, &CClientDlg::OnBnClickedButtonLoad)
	ON_BN_CLICKED(IDC_BUTTON_UNLOAD, &CClientDlg::OnBnClickedButtonUnload)
	ON_BN_CLICKED(IDC_BUTTON1, &CClientDlg::OnBnClickedButton1)
	ON_NOTIFY(NM_RCLICK, IDC_LIST_PROCESS_LIST, &CClientDlg::OnNMRClickListProcessList)
	ON_BN_CLICKED(IDC_BUTTON2, &CClientDlg::OnBnClickedButton2)
END_MESSAGE_MAP()


// CClientDlg 消息处理程序

BOOL CClientDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	InitProcessList();

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CClientDlg::OnPaint()
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
HCURSOR CClientDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CClientDlg::InitProcessList()
{
	//LONG lStyle;
	//lStyle = GetWindowLong(m_process_list.m_hWnd, GWL_STYLE);//获取当前窗口style
	//lStyle &= ~LVS_TYPEMASK; //清除显示方式位
	//lStyle |= LVS_REPORT; //设置style
	//lStyle |= LVS_SINGLESEL;//单选模式
	//SetWindowLong(m_process_list.m_hWnd, GWL_STYLE, lStyle);//设置style

	m_process_list.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	m_process_list.InsertColumn(0, L"进程ID", LVCFMT_LEFT, -1, 0);
	m_process_list.InsertColumn(1, L"进程名", LVCFMT_LEFT, -1, 1);
	m_process_list.SetColumnWidth(0, 50);
	m_process_list.SetColumnWidth(1, 110);


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
		m_process_list.InsertItem(i, std::to_wstring(pe32.th32ProcessID).c_str());
		m_process_list.SetItemText(i, 1, pe32.szExeFile);

		bMore = Process32Next(hProcessSnap, &pe32);
		i++;
	}
	//清除snapshot对象
	CloseHandle(hProcessSnap);
}

void CClientDlg::OnLvnItemchangedListProcessList(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;
}


void CClientDlg::OnBnClickedButtonLoad()
{
	if (!load_drv::load())
	{
		::MessageBox(NULL, L"驱动加载失败!", NULL, 0);
	}
}


void CClientDlg::OnBnClickedButtonUnload()
{
	load_drv::unload();
}


void CClientDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码

	int row = m_process_list.GetSelectionMark();
	if (row < 0)
	{
		MessageBox(L"请选择调试进程");
		return;
	}
	CString cs_debugee_pid = m_process_list.GetItemText(row, 0);

	CString cs_debugger_pid;
	m_debugger_pid.GetWindowTextW(cs_debugger_pid);

	std::wstring ws_debugee_pid = cs_debugee_pid.GetBuffer();
	std::wstring ws_debugger_pid = cs_debugger_pid.GetBuffer();

	uint64_t debugee_pid = std::stoull(ws_debugee_pid);
	uint64_t debugger_pid = std::stoull(ws_debugger_pid);

	kernel_msg kmsg;
	kmsg.start_debugger(debugger_pid, debugee_pid);

	HMODULE hNtdll = LoadLibrary(L"ntdll.dll");
	if (hNtdll)
	{
		PVOID proc_DbgUiRemoteBreakin = GetProcAddress(hNtdll, "DbgUiRemoteBreakin");

		DWORD OldProtection = 0;
		VirtualProtect(proc_DbgUiRemoteBreakin, 0x100, PAGE_EXECUTE_READWRITE, &OldProtection);
		*((PUCHAR)proc_DbgUiRemoteBreakin + 17) = 0x74;

		//PVOID proc_RtlExitUserProcess = GetProcAddress(hNtdll, "RtlExitUserProcess");
		FreeLibrary(hNtdll);

		kmsg.hook_r3(debugee_pid, proc_DbgUiRemoteBreakin, nullptr);
		//kmsg.hook_r3(debugee_pid, proc_RtlExitUserProcess, nullptr);
	}

	HMODULE hKernelBase = LoadLibrary(L"kernelbase.dll");

	// 调试器附加时，会调用ProcessIdToHandle，如果有保护会返回0，这里修改这些代码
	PCHAR proc_DebugActiveProcess = (PCHAR)GetProcAddress(hKernelBase, "DebugActiveProcess");

	HANDLE hDebugger = OpenProcess(PROCESS_ALL_ACCESS, FALSE, debugger_pid);

	DWORD OldProtection = 0;
	VirtualProtect(proc_DebugActiveProcess, 0x100, PAGE_EXECUTE_READWRITE, &OldProtection);

	uint16_t nop_code = 0x9090;
	WriteProcessMemory(hDebugger, proc_DebugActiveProcess + 0x34, &nop_code, 2, NULL);

	CloseHandle(hDebugger);

	FreeLibrary(hKernelBase);

}


void CClientDlg::OnNMRClickListProcessList(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	
	m_process_list.DeleteAllItems();
	m_process_list.DeleteColumn(1);
	m_process_list.DeleteColumn(0);
	
	InitProcessList();

	*pResult = 0;
}


void CClientDlg::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码

	int row = m_process_list.GetSelectionMark();
	if (row < 0)
	{
		MessageBox(L"请选择申请内存进程");
		return;
	}

	CString cs_avm_pid = m_process_list.GetItemText(row, 0);

	std::wstring ws_avm_pid = cs_avm_pid.GetBuffer();

	uint64_t avm_pid = std::stoull(ws_avm_pid);

	void *base_address = nullptr;

	kernel_msg kmsg;
	kmsg.allocate_vm(avm_pid, &base_address);

	std::wstringstream ss;
	std::wstring ws_base_address;

	ss << "0x" << std::hex << (uint64_t)base_address;

	ss >> ws_base_address;

	m_allocated_vm_edit.SetWindowTextW(ws_base_address.c_str());
}
