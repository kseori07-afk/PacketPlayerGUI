import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QTableWidget, QTableWidgetItem, QFileDialog,
                             QLabel, QSplitter, QTextEdit, QComboBox, QLineEdit, QGroupBox, QMessageBox,
                             QAbstractItemView)
from PyQt6.QtCore import Qt
from scapy.all import *
from modules import loader, viewer, editor, sender

class PacketToolGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.packet_list = []  # 현재 로드된 패킷 리스트
        self.current_pkt_idx = -1 #현재 선택된 패킷 인덱스
        self.initUI()

    def initUI(self):
        self.setWindowTitle("PPlayer")
        self.resize(1000,700)

        ########## 메인 레이아웃 설정 ##########
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)

        ########## 1. 상단 메뉴 영역 (파일 로드/저장) ##########
        top_layout = QHBoxLayout()
        btn_load = QPushButton("pcap 파일 열기")
        btn_load.clicked.connect(self.load_file)
        btn_save = QPushButton("pcap 파일 저장")
        btn_save.clicked.connect(self.save_file)
        self.lbl_status = QLabel("준비")

        top_layout.addWidget(btn_load)
        top_layout.addWidget(btn_save)
        top_layout.addWidget(self.lbl_status)
        top_layout.addStretch(1)
        main_layout.addLayout(top_layout)

        ########## 메인 콘텐츠 (좌측 리스트 / 우측 패킷 상세정보, 패킷 수정) ##########
        splitter = QSplitter(Qt.Orientation.Horizontal)
        ########## 패킷 리스트 테이블 ##########
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(["번호", "시각", "출발지 IP", "목적지 IP", "프로토콜", "길이", "상세정보"])
        self.table.cellClicked.connect(self.on_table_click)  # 클릭 이벤트 연결
        splitter.addWidget(self.table)
        ########## 상세 정보 및 편집기 ##########
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)

        ########## 상세 정보 뷰어 ##########
        self.txt_detail = QTextEdit()
        self.txt_detail.setReadOnly(True)
        right_layout.addWidget(QLabel("<b>패킷 정보</b>"))
        right_layout.addWidget(self.txt_detail)

        ########### 패킷 편집기 (GroupBox) ##########
        edit_group = QGroupBox("패킷 수정")
        edit_layout = QVBoxLayout()

        ########### 편집 대상 선택 ##########
        self.combo_edit_target = QComboBox()
        self.combo_edit_target.addItems([
            "출발지 MAC", "목적지 MAC",
            "출발지 IP", "목적지 IP",
            "출발지 포트", "목적지 포트",
            "HTTP 메소드", "HTTP 호스트", "HTTP 경로",
            "HTTP 응답 코드", "HTTP 응답 상태"
        ])
        edit_layout.addWidget(QLabel("변경 필드:"))
        edit_layout.addWidget(self.combo_edit_target)

        ########## 수정 값 입력 ##########
        self.input_edit_val = QLineEdit()
        self.input_edit_val.setPlaceholderText("변경할 내용")
        edit_layout.addWidget(QLabel("변경 후"))
        edit_layout.addWidget(self.input_edit_val)

        ########## 적용 버튼 ##########
        btn_apply = QPushButton("적용")
        btn_apply.clicked.connect(self.apply_modification)
        edit_layout.addWidget(btn_apply)

        edit_group.setLayout(edit_layout)
        right_layout.addWidget(edit_group)

        splitter.addWidget(right_widget)
        splitter.setSizes([600, 400])  # 초기 비율 설정
        main_layout.addWidget(splitter)

        ########## 패킷 전송 ##########
        replay_group = QGroupBox("패킷 전송")
        replay_layout = QHBoxLayout()

        replay_layout.addWidget(QLabel("인터페이스:"))
        self.combo_iface = QComboBox()
        self.load_interfaces()  # 인터페이스 목록 로드
        replay_layout.addWidget(self.combo_iface)

        replay_layout.addWidget(QLabel("전송 횟수:"))
        self.input_count = QLineEdit("1")
        self.input_count.setFixedWidth(50)
        replay_layout.addWidget(self.input_count)

        btn_send_one = QPushButton("선택된 패킷 전송")
        btn_send_one.clicked.connect(self.send_selected)
        replay_layout.addWidget(btn_send_one)

        btn_send_all = QPushButton("모든 패킷 전송")
        btn_send_all.clicked.connect(self.send_all)
        replay_layout.addWidget(btn_send_all)

        replay_group.setLayout(replay_layout)
        main_layout.addWidget(replay_group)

    ########## 기능 구현 ##########
    def load_interfaces(self):
        ifaces = sender.get_interfaces()
        for name, desc in ifaces:
            self.combo_iface.addItem(desc, userData=name)  # userData에 실제 시스템 이름 저장
    ########## 파일 로드 ##########
    def load_file(self):
        fpath, _ = QFileDialog.getOpenFileName(self, "Open PCAP", "", "PCAP Files (*.pcap *.pcapng)")
        if fpath:
            self.lbl_status.setText("Loading...")
            pkts = loader.load_pcap(fpath)
            if pkts:
                self.packet_list = list(pkts)  # Scapy PacketList -> Python List
                self.update_table()
                self.lbl_status.setText(f"Loaded {len(self.packet_list)} packets from {fpath}")
            else:
                self.lbl_status.setText("Failed to load file.")
    ########## 파일 저장 ##########
    def save_file(self):
        if not self.packet_list: return
        fpath, _ = QFileDialog.getSaveFileName(self, "Save PCAP", "", "PCAP Files (*.pcap)")
        if fpath:
            success, msg = loader.save_pcap(self.packet_list, fpath)
            QMessageBox.information(self, "Save", msg)

    ########## 테이블 업데이트 ##########
    def update_table(self):
        self.table.setRowCount(len(self.packet_list))
        self.table.setSortingEnabled(False)

        for i, pkt in enumerate(self.packet_list):
            # viewer 모듈에서 요약 정보 가져오기
            data = viewer.pcapViewer(i, pkt)
            for j, val in enumerate(data):
                self.table.setItem(i, j, QTableWidgetItem(str(val)))

        self.table.resizeColumnsToContents()

    ########## 항목 클릭시 (상세 정보 표시) ##########
    def on_table_click(self, row, col):
        self.current_pkt_idx = row
        pkt = self.packet_list[row]
        # viewer 모듈에서 상세 정보 텍스트 가져오기
        detail_text = viewer.packetViewer(pkt)
        self.txt_detail.setText(detail_text)

    ########## 수정 사항 적용 ##########
    def apply_modification(self):
        if self.current_pkt_idx < 0:
            QMessageBox.warning(self, "경고", "패킷을 선택하세요")
            return

        pkt = self.packet_list[self.current_pkt_idx]
        target = self.combo_edit_target.currentText()
        val = self.input_edit_val.text()

        if not val:
            return
        try:
            # editor 모듈의 함수 호출
            if target == "출발지 MAC":
                pkt = editor.modify_MAC(pkt, 'src', val)
            elif target == "목적지 MAC":
                pkt = editor.modify_MAC(pkt, 'dst', val)
            elif target == "출발지 IP":
                pkt = editor.modify_IP(pkt, 'src', val)
            elif target == "목적지 IP":
                pkt = editor.modify_IP(pkt, 'dst', val)
            elif target == "출발지 포트":
                pkt = editor.modify_Port(pkt, 'src', val)
            elif target == "목적지 포트":
                pkt = editor.modify_Port(pkt, 'dst', val)
            elif target.startswith("HTTP"):
                # "HTTP Method" -> "Method"
                if target.split()[1] == "메소드":
                    pkt = editor.modify_HTTP(pkt, 'Method', val)
                if target.split()[1] == "호스트":
                    pkt = editor.modify_HTTP(pkt, 'Host', val)
                if target.split()[1] == "경로":
                    pkt = editor.modify_HTTP(pkt, 'Path', val)
                if target.split()[2] == "코드":
                    pkt = editor.modify_HTTP(pkt, 'Status Code', val)
                if target.split()[2] == "상태":
                    pkt = editor.modify_HTTP(pkt, 'Reason Phrase', val)

            # 리스트 업데이트 및 테이블 새로고침
            self.packet_list[self.current_pkt_idx] = pkt
            self.update_table()  # 전체 갱신 (부분 갱신으로 최적화 가능)
            self.table.selectRow(self.current_pkt_idx)  # 선택 유지
            self.on_table_click(self.current_pkt_idx, 0)  # 상세 뷰 갱신

            QMessageBox.information(self, "성공", f"{target} 수정 완료")

        except Exception as e:
            QMessageBox.critical(self, "에러", str(e))

    ########## 인터페이스 선택 ##########
    def get_selected_iface(self):
        return self.combo_iface.currentData()  # userData에 있는 실제 이름 반환

    ########## 선택된 패킷 전송 ##########
    def send_selected(self):
        if self.current_pkt_idx < 0: return
        iface = self.get_selected_iface()
        cnt = int(self.input_count.text())
        pkt = self.packet_list[self.current_pkt_idx]

        success, msg = sender.send_packet(pkt, iface, cnt)
        if not success:
            QMessageBox.critical(self, "에러", msg)
        else:
            self.lbl_status.setText(f"패킷 #{self.current_pkt_idx + 1} 전송")

    ########## 모든 패킷 전송 ##########
    def send_all(self):
        if not self.packet_list: return
        iface = self.get_selected_iface()
        cnt = int(self.input_count.text())

        success, msg = sender.relay_packet(self.packet_list, iface, cnt)
        if not success:
            QMessageBox.critical(self, "에러", msg)
        else:
            QMessageBox.information(self, "성공", msg)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = PacketToolGUI()
    ex.show()
    sys.exit(app.exec())