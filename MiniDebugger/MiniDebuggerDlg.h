
// MiniDebuggerDlg.h: 头文件
//

#pragma once


// CMiniDebuggerDlg 对话框
class CMiniDebuggerDlg : public CDialogEx
{
// 构造
public:
	CMiniDebuggerDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MINIDEBUGGER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持

private:
	void InitProcessList();
	DWORD GetDebuggerPid();

	DWORD HandleDebugEvent(DEBUG_EVENT &);

// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_list_process;
	afx_msg void OnNMRClickListProcess(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnBnClickedButton1();
	CEdit m_edit_event;
	afx_msg void OnBnClickedButton2();
};
