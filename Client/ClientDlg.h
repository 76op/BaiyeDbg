
// ClientDlg.h: 头文件
//

#pragma once


// CClientDlg 对话框
class CClientDlg : public CDialogEx
{
// 构造
public:
	CClientDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_CLIENT_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_process_list;

private:
	void InitProcessList();
public:
	afx_msg void OnLvnItemchangedListProcessList(NMHDR *pNMHDR, LRESULT *pResult);
	CEdit m_debugger_pid;
	afx_msg void OnBnClickedButtonLoad();
	afx_msg void OnBnClickedButtonUnload();
	afx_msg void OnBnClickedButton1();
	afx_msg void OnNMRClickListProcessList(NMHDR *pNMHDR, LRESULT *pResult);
	CEdit m_allocated_vm_edit;
	afx_msg void OnBnClickedButton2();
};
