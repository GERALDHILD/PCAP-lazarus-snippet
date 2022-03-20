unit umain;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, Buttons, StdCtrls,
  ExtCtrls, pcap //,Sockets
  {$ifdef LINUX}
  ,netdb
  {$else}
  ,JwaWinSock2,JwaWinType,JwaWS2tcpip
  //,synsock
  {$endif}

  ;

type

  { TFMain }

  TFMain = class(TForm)
    B_CloseLink: TButton;
    B_FindDevs: TButton;
    B_OPenLink: TBitBtn;
    CB_Devices: TComboBox;
    GroupBox1: TGroupBox;
    GroupBox2: TGroupBox;
    Memo1: TMemo;
    T_Update: TTimer;
    procedure B_CloseLinkClick(Sender: TObject);
    procedure B_FindDevsClick(Sender: TObject);
    procedure B_OPenLinkClick(Sender: TObject);
    procedure CB_DevicesSelect(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure T_UpdateTimer(Sender: TObject);
  private
    Caracteristique : TStringList;
  public
    dev, devs : ppcap_if;
    err : PChar;
    t : string;
    count : word;
    adHandle : PPcap;
  end;

var
  FMain: TFMain;
  function iptos(ip : longword) : string;
  function ip6tos(sockaddress : psockaddr) : string;
  procedure ifprint( d : ppcap_if; var List : TStringList);

implementation

{$R *.frm}

//*****************************************************************************
// @fn
// @brief
// @param
// @return
//*****************************************************************************
function ByteToHex(octet : byte) : string;
var
  o : byte;
begin
  o:=(octet and $F0) shr 4;
  if o<=9 then
    begin
      Result:=chr(o+48);
    end else
    begin
      Result:=chr(o+55);
    end;
  o:=octet and $0F;
  if o<=9 then
    begin
      Result:=Result+chr(o+48);
    end else
    begin
      Result:=Result+chr(o+55);
    end;
end;

//*****************************************************************************
// @fn
// @brief
// @param
// @return
//*****************************************************************************
function iptos(ip : longword) : string;
var octet : byte;
begin
  octet := (ip and $000000FF) ;
  Result:=inttostr(octet)+'.';
  octet := (ip and $0000FF00) shr 8;
  Result:=Result+inttostr(octet)+'.';
  octet := (ip and $00FF0000) shr 16;
  Result:=Result+inttostr(octet)+'.';
  octet := (ip and $FF000000) shr 24;
  Result:=Result+inttostr(octet);
end;


//*****************************************************************************
// @fn
// @brief
// @param
// @return
//*****************************************************************************
function ip6tos(sockaddress: psockaddr): string;
var
  sockaddrlen : integer;
  ip6str : array[0..127] of char;
begin
  {$ifdef WINDOWS}
  sockaddrlen := sizeof(TSockAddrIn6);
  {$else}
  sockaddrlen := sizeof(sockaddr_storage);
  {$endif}
  Result:='';
  // function getnameinfo(sa: PSockAddr; salen: socklen_t; host: PChar; hostlen: DWORD; serv: PChar; servlen: DWORD; flags: Integer): Integer; stdcall;
  if getnameinfo(sockaddress,sockaddrlen, @ip6str[0],sizeof(ip6str),nil,0,NI_NUMERICHOST) <> 0 then
    begin
      Result:='';
    end else
    begin
      Result:=StrPas(@ip6Str[0]);
    end;

end;

//*****************************************************************************
// @fn
// @brief
// @param
// @return
//*****************************************************************************
procedure ifprint( d : ppcap_if; var List : TStringList);
var a : PPcap_Addr;
  ip6str : string;
  i : integer;
  u32 : longword;
begin
  List.Clear;

  // Name
  List.Add(StrPas(d^.name));

  // Description
  List.Add(StrPas(d^.description));

  // Loopback Address
  if (d^.flags and PCAP_IF_LOOPBACK) <> 0 then
    begin
      List.Add('Loopback : yes');
    end else
    begin
      List.Add('Loopback : no');
    end;
  // IP Address
  a:=d^.addresses;
  while a<>nil do
    begin
      i:=a^.addr^.sa_family;
      List.Add('Address family :#'+inttostr(i));
      case i of
        AF_INET : begin
          List.Add('Address family : INET');
          if a^.addr <> nil then
            begin
              u32:=a^.addr^.sin_addr.s_addr;
              List.Add('Address IP :'+iptos(u32));
            end;
          if a^.netmask <> nil then
            begin
              u32:=a^.netmask^.sin_addr.s_addr;
              List.Add('Netmask :'+iptos(u32));
            end;
          if a^.broadaddr <> nil then
            begin
              u32:=a^.broadaddr^.sin_addr.s_addr;
              List.Add('Broadcast Address :'+iptos(u32));
            end;

        end;
        AF_INET6 : begin
          List.Add('Address family : INET6');
          if a^.addr <> nil then
            begin
              ip6str:=ip6tos(PSockAddr(a^.addr));// SocketGetNameInfo(a^.addr^); //ip6tos(a^.addr);
              List.Add('Address IPv6 :'+ip6str);
            end;
        end;
      end;


      a:=a^.next;
    end;
end;

{ TFMain }

//*****************************************************************************
// @fn
// @brief
// @param
// @return
//*****************************************************************************
procedure TFMain.B_OPenLinkClick(Sender: TObject);
var
  errbuf : array[0..PCAP_ERRBUF_SIZE] of char;
begin
  if dev = nil then
    begin
      Application.MessageBox('Il faut d''abord sélectionner une interface avant de l''ouvrir','Erreur',0);
      exit;
    end;
  adHandle := pcap_open_live(
                dev^.name,      // name of the device
                65536,          // portion of the packet to capture. 65536 grants that the whole packet will be captured on all the MACs.
                1,              // promiscuous mode (nonzero means promiscuous)
                1000,           // read timeout
                @errbuf[0]);    // error buffer
  if adHandle = nil then
    begin
      Application.MessageBox('Impossible d''ouvrir le port','Erreur',0);
      exit;
    end;
  T_Update.Enabled:=True;
  B_CloseLink.Enabled:=True;
end;

//*****************************************************************************
// @fn
// @brief
// @param
// @return
//*****************************************************************************
procedure TFMain.CB_DevicesSelect(Sender: TObject);
var i : integer;
begin
  dev := devs;
  for i:=0 to CB_Devices.ItemIndex-1 do dev := dev^.next;
  ifPrint(dev,Caracteristique);
  Memo1.Clear;
  Memo1.Lines.Assign(Caracteristique);
  B_OpenLink.Enabled:=True;
  B_CloseLink.Enabled:=False;
  //for i:=0 to Caracteristique.Count-1 do
  //  begin
  //    Memo1.Lines.Add(Caracteristique.Strings[i]);
  //  end;
end;

//*****************************************************************************
// @fn
// @brief
// @param
// @return
//*****************************************************************************
procedure TFMain.FormCreate(Sender: TObject);
begin
  Caracteristique := TStringList.Create;
  adHandle := nil;
  B_CloseLink.Enabled:=False;
  B_OpenLink.Enabled:=False;
end;

//*****************************************************************************
// @fn
// @brief
// @param
// @return
//*****************************************************************************
procedure TFMain.FormDestroy(Sender: TObject);
begin
  Caracteristique.Free;
end;

//*****************************************************************************
// @fn
// @brief
// @param
// @return
//*****************************************************************************
procedure TFMain.T_UpdateTimer(Sender: TObject);
var
  res : Longint;
  //struct pcap_pkthdr *header;
  //const u_char *pkt_data;
  header : PPcap_Pkthdr;
  pkt_data : PChar;
  s : string;
  i : integer;
begin
  T_Update.Enabled:=False;
  if adhandle = nil then exit;
  ///* Retrieve the packets */
  repeat
    res:=pcap_next_ex(adHandle, @header, @pkt_data);
    if res>0 then
      begin
        res := pcap_datalink(adHandle);
        s:=strpas(pcap_datalink_val_to_name(res));
        Memo1.Lines.Add('Datalink : '+s);
        s:='HEADER ts='+inttostr(header^.ts.tv_sec)+'; ';

        s:=s+' caplen = '+inttostr(header^.caplen)+'; len = '+inttostr(header^.len)+' | ';
        //s:=s + strpas(pkt_data);
        s:=s+' DATAS:';
        for i:=0 to header^.len-1 do
          begin
            s:=s+byteToHex(BYTE((pkt_data+i)^))+' ';
          end;
        Memo1.Lines.Add(s);
      end;
  until res<=0;
  if (res < 0 ) then
    begin
      Application.MessageBox('Error when reding frame. Stop the receive. ','Error',0);
      exit;
    end;
  T_Update.Enabled:=True;

end;

//*****************************************************************************
// @fn
// @brief
// @param
// @return
//*****************************************************************************
procedure TFMain.B_FindDevsClick(Sender: TObject);
var
  ad : Longword;
begin
  CB_Devices.Clear;
  CB_Devices.Text:='';
  if(pcap_findalldevs(@devs, err) = -1) then
    begin
      Application.MessageBox('Error in pcap_findalldevs: ','Error',0);
    end;
  {-- choose which device to monitor --}
  dev := devs;
  count := 0;
  repeat
    t:=StrPas(dev^.name)+'|'+StrPas(dev^.description);
    CB_Devices.Items.Add(t);
    dev := dev^.next;
    inc(count);
  until dev = nil;
  B_OpenLink.Enabled:=False;
end;

//*****************************************************************************
// @fn
// @brief
// @param
// @return
//*****************************************************************************
procedure TFMain.B_CloseLinkClick(Sender: TObject);
begin
  T_Update.Enabled:=True;
  pcap_close(adhandle);
  adhandle := nil;
  B_CloseLink.Enabled:=False;
end;

//*****************************************************************************
// @fn
// @brief
// @param
// @return
//*****************************************************************************
end.

