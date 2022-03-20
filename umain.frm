object FMain: TFMain
  Left = 0
  Height = 460
  Top = 0
  Width = 1116
  Caption = 'Test de l''aquisition des trames Ethernet avec NPCAP'
  ClientHeight = 460
  ClientWidth = 1116
  DesignTimePPI = 120
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  LCLVersion = '7.5'
  object GroupBox1: TGroupBox
    Left = 0
    Height = 131
    Top = 0
    Width = 1116
    Align = alTop
    Caption = 'GroupBox1'
    ClientHeight = 106
    ClientWidth = 1112
    TabOrder = 0
    object B_OPenLink: TBitBtn
      Left = 896
      Height = 38
      Top = 19
      Width = 94
      Caption = 'Openlink'
      OnClick = B_OPenLinkClick
      TabOrder = 0
    end
    object CB_Devices: TComboBox
      Left = 15
      Height = 28
      Top = 29
      Width = 753
      Anchors = [akTop, akLeft, akRight]
      ItemHeight = 20
      OnSelect = CB_DevicesSelect
      TabOrder = 1
      Text = 'CB_Devices'
    end
    object B_FindDevs: TButton
      Left = 792
      Height = 31
      Top = 24
      Width = 94
      Anchors = [akTop, akRight]
      Caption = 'Find Alldev'
      OnClick = B_FindDevsClick
      TabOrder = 2
    end
    object B_CloseLink: TButton
      Left = 1000
      Height = 31
      Top = 22
      Width = 94
      Caption = 'CloseLink'
      OnClick = B_CloseLinkClick
      TabOrder = 3
    end
  end
  object GroupBox2: TGroupBox
    Left = 0
    Height = 329
    Top = 131
    Width = 1116
    Align = alClient
    Caption = 'GroupBox2'
    ClientHeight = 304
    ClientWidth = 1112
    TabOrder = 1
    object Memo1: TMemo
      Left = 0
      Height = 304
      Top = 0
      Width = 1112
      Align = alClient
      Lines.Strings = (
        'Memo1'
      )
      TabOrder = 0
    end
  end
  object T_Update: TTimer
    Enabled = False
    Interval = 100
    OnTimer = T_UpdateTimer
    Left = 781
    Top = 109
  end
end
