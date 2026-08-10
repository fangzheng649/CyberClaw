"""TP-LINK 交换机 web 端口隔离（selenium 驱动 Edge）。

通过交换机 web 界面 shutdown/undo 端口，实现**真物理隔离**：端口 disable 后，
该端口下挂的设备从网络消失（ping 不可达）。这是设备级真隔离，评委可现场复验。

为什么用 selenium 而非 HTTP API：该交换机（TL-SG2210LPF）的 web 登录 POST
对非浏览器请求一律断开连接（反自动化），httpx/requests/curl/raw-socket 全失败；
且设备无 SSH/SNMP/Telnet。唯一能自动化的是真浏览器驱动 —— selenium 驱动的就是
真 Edge，设备无法区分、无法拒绝。

凭证从环境变量读取：SWITCH_IP / SWITCH_WEB_USER / SWITCH_WEB_PASS。
"""
import logging
import os
import re
import threading
import time

logger = logging.getLogger(__name__)

SWITCH_IP = os.getenv("SWITCH_IP", "192.168.1.1")
SWITCH_USER = os.getenv("SWITCH_WEB_USER", "admin")
SWITCH_PASS = os.getenv("SWITCH_WEB_PASS", "")

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import Select
    _SELENIUM_AVAILABLE = True
except ImportError:
    webdriver = None
    By = None
    Select = None
    _SELENIUM_AVAILABLE = False

_PORT_DIGIT_RE = re.compile(r"(\d+)")


def _parse_port_number(port_label) -> int | None:
    """从端口标签提取端口号：'Port 1' → 1, '3' → 3, 'local'/'' → None。"""
    if not port_label:
        return None
    m = _PORT_DIGIT_RE.search(str(port_label))
    return int(m.group(1)) if m else None


class TPLinkWebIsolator:
    """selenium 驱动 Edge 登录交换机 web，shutdown/undo 指定端口。

    Session 复用：保持一个登录态 headless Edge 常驻，隔离/恢复时复用
    （省掉每次"启动 Edge + 登录"的 ~10s），单次操作 ~5s。后端启动时预热
    （ensure_session，后台不阻塞）。自动处理 session 过期重登、Edge 崩溃重建、
    并发排队（_lock —— 同一 driver 不能并发操作）。
    """

    def __init__(self):
        self._driver = None
        self._lock = threading.Lock()

    def _create_driver(self):
        if not _SELENIUM_AVAILABLE:
            raise RuntimeError("selenium 未安装：pip install selenium")
        opts = webdriver.EdgeOptions()
        opts.add_argument("--headless=new")
        opts.add_argument("--window-size=1280,800")
        opts.add_argument("--disable-gpu")
        # eager: 等 DOMContentLoaded 而非满 load —— TP-LINK 的 frame 文档慢，
        # normal 策略下 switch_to.frame 要 ~5s/次；eager 大幅加速（元素靠 implicit_wait 兜底）。
        opts.page_load_strategy = "eager"
        drv = webdriver.Edge(options=opts)
        # 关键：页面加载超时。TP-LINK 偶发页面 hang 会让 drv.get() 无限阻塞，
        # 卡到 call_tool 的 120s 超时。设 20s 兜底。
        drv.set_page_load_timeout(20)
        drv.implicitly_wait(5)
        return drv

    def _login(self, drv) -> bool:
        drv.get(f"http://{SWITCH_IP}/")
        time.sleep(2)
        drv.find_element(By.ID, "username").send_keys(SWITCH_USER)
        drv.find_element(By.ID, "plain_password").send_keys(SWITCH_PASS)
        drv.find_element(By.ID, "logon").click()
        time.sleep(3)
        src = drv.page_source
        return "mainFrame" in src or "Top.htm" in src

    def _is_session_alive(self) -> bool:
        """复用的 driver 是否仍健康且处于登录态。

        用 execute_script 数 frame（登录后是 frameset，登录页是单表单无 frame），
        避免 page_source 序列化整个 frameset 的 ~10s 开销。
        """
        drv = self._driver
        if drv is None:
            return False
        try:
            n = drv.execute_script(
                "return document.getElementsByTagName('frame').length")
            return n and n > 0
        except Exception:
            return False

    def _close(self):
        if self._driver is not None:
            try:
                self._driver.quit()
            except Exception:
                pass
            self._driver = None

    def _build_session(self) -> bool:
        """创建并登录一个新 driver（调用方需持 _lock）。"""
        self._close()
        try:
            drv = self._create_driver()
        except Exception as e:
            logger.error(f"TPLink 创建 Edge 失败: {e}")
            return False
        if self._login(drv):
            self._driver = drv
            logger.info(f"TPLink web session 已建立 (switch={SWITCH_IP})")
            return True
        try:
            drv.quit()
        except Exception:
            pass
        return False

    def ensure_session(self) -> bool:
        """（公开）确保有健康登录态的复用 driver。后端启动时预热调用，
        交换机不可达/凭证错不阻塞后端（返回 False）。"""
        if not _SELENIUM_AVAILABLE or not SWITCH_PASS:
            return False
        with self._lock:
            if self._is_session_alive():
                return True
            return self._build_session()

    def set_port(self, port: int, enabled: bool) -> dict:
        """设置交换机端口状态（复用常驻 session，JS 跨 frame 操作 ~2-3s）。

        用 execute_script 在 frameset 各 frame 直接操作，避开 switch_to.frame
        的 ~5s/次开销（selenium 等待 frame 文档 ready，TP-LINK 嵌入式慢）。

        Args:
            port: 端口号（1..N）
            enabled: True=启用(undo shutdown), False=禁用(shutdown, 设备断网)
        Returns:
            {status: applied|error, port, enabled, method, ...}
        """
        if not SWITCH_PASS:
            return {"status": "error", "message": "SWITCH_WEB_PASS 未配置（交换机 web 密码）"}
        if not _SELENIUM_AVAILABLE:
            return {"status": "error", "message": "selenium 未安装：pip install selenium"}

        with self._lock:  # 同一 driver 不能并发操作，序列化
            if not self._is_session_alive():
                if not self._build_session():
                    return {"status": "error",
                            "message": f"交换机登录失败（{SWITCH_IP}，检查 SWITCH_WEB_USER/PASS/网络）"}
            drv = self._driver
            state_val = "1" if enabled else "0"
            try:
                # 1) JS 在 bottomLeftFrame click 端口设置菜单（不 switch_to.frame）
                clicked = drv.execute_script(
                    "var f=frames['bottomLeftFrame'];if(!f)return false;"
                    "var l=f.document.getElementsByTagName('a');"
                    "for(var i=0;i<l.length;i++){if(l[i].href.indexOf('PortSettingRpm')>=0){l[i].click();return true;}}"
                    "return false;")
                if not clicked:
                    return {"status": "error", "message": "找不到端口设置菜单（PortSettingRpm）"}
                # 2) poll 等 mainFrame 加载完 PortSettingRpm（do_submit 定义 + portSel 有 options）
                ready = False
                for _ in range(30):  # ~9s 上限
                    try:
                        ready = drv.execute_script(
                            "try{return typeof frames['mainFrame'].do_submit!=='undefined'"
                            "&&frames['mainFrame'].document.getElementById('portSel')"
                            "&&frames['mainFrame'].document.getElementById('portSel').options.length>0}"
                            "catch(e){return false}")
                        if ready:
                            break
                    except Exception:
                        pass
                    time.sleep(0.3)
                if not ready:
                    return {"status": "error", "message": "端口设置页未就绪（PortSettingRpm 加载超时）"}
                # 3) JS 设 portid + state，调 do_submit（填 token + 浏览器原生提交，设备接受）
                drv.execute_script(
                    f"var f=frames['mainFrame'],d=f.document,p=d.getElementById('portSel');"
                    f"for(var i=0;i<p.options.length;i++){{p.options[i].selected=(p.options[i].value==='{port}');}}"
                    f"d.querySelector('select[name=state]').value='{state_val}';"
                    f"f.do_submit();")
                time.sleep(2)  # 等提交生效
                action = "undo shutdown" if enabled else "shutdown"
                logger.info(f"TPLink port {port} {action} via JS (switch={SWITCH_IP})")
                return {"status": "applied", "port": port, "enabled": enabled,
                        "method": "web_port_shutdown", "switch": SWITCH_IP}
            except Exception as e:
                logger.error(f"TPLink set_port(port={port},enabled={enabled}) failed: {e}")
                self._close()
                return {"status": "error", "message": f"{type(e).__name__}: {e}"}

    def shutdown(self):
        """后端关闭时释放常驻 driver。"""
        with self._lock:
            self._close()


_isolator: TPLinkWebIsolator | None = None


def get_tplink_isolator() -> TPLinkWebIsolator:
    global _isolator
    if _isolator is None:
        _isolator = TPLinkWebIsolator()
    return _isolator
