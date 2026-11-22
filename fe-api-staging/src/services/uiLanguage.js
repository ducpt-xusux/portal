// Presentation labels only. Never use translated labels as API values or keys.
import { fieldLabels, sourceErrors, valueLabels } from './uiGlossary.js'
const normalizedFields = Object.fromEntries(Object.entries(fieldLabels).map(([key, value]) => [key.trim().toLowerCase(), value]))
const signalNames = {
  'CORR-001': 'Vi phạm chính sách lặp lại',
  'CORR-002': 'Dấu hiệu chèn mã SQL lặp lại',
  'CORR-003': 'Truy cập dữ liệu nhạy cảm lặp lại',
  'CORR-004': 'Kết hợp nhiều kỹ thuật',
  'CORR-005': 'Lỗi tương thích giao thức lặp lại',
  'CORR-012': 'Truy cập từ nguồn không được phép',
  'CORR-013': 'Chèn mã SQL từ nguồn không được phép',
  'CORR-014': 'Dò tìm cấu trúc lặp lại',
  'CORR-015': 'Dò tìm rồi thử hành vi nguy hiểm',
  'CORR-022': 'Chuỗi hành vi tăng mức nguy hiểm',
}
export function signalName(code) {
  return Object.hasOwn(signalNames, code) ? signalNames[code] : null
}
const labels = {
  administrative: 'Quản trị',
  allow: 'Cho phép',
  authorization: 'Phân quyền',
  identity: 'Định danh nguồn',
  injection: 'Dấu hiệu chèn SQL',
  policy: 'Chính sách',
  reconnaissance: 'Thăm dò',
  'Administrative SHOW statement detected': 'Phát hiện lệnh SHOW dùng cho quản trị',
  'Approved health query': 'Truy vấn kiểm tra hoạt động được phép',
  'Approved reader workload': 'Truy vấn thuộc phạm vi đọc được phép',
  'Approved writer read workload': 'Tài khoản ghi được phép thực hiện truy vấn đọc này',
  'Approved order status update': 'Cập nhật trạng thái đơn hàng được phép',
  'Reader attempted a write operation': 'Tài khoản chỉ đọc đã yêu cầu ghi dữ liệu',
  'Query originated from an unexpected source': 'Truy vấn đến từ nguồn ngoài phạm vi cho phép',
  'System schema enumeration or access': 'Có truy vấn liệt kê hoặc truy cập cấu trúc dữ liệu hệ thống',
  'Tautological predicate detected': 'Phát hiện điều kiện luôn đúng',
  'Constant-true predicate within compound WHERE': 'Phát hiện điều kiện luôn đúng trong mệnh đề WHERE kết hợp',
  'Request was blocked by the P14 default-deny policy': 'Yêu cầu bị chặn theo chính sách chặn mặc định',
  REVIEWED_REPORT_EVIDENCE: 'Bằng chứng đã đối chiếu nguồn',
  LIVE_READONLY: 'Nguồn thật, chỉ đọc',
  READONLY_COLLECTOR_HASH_CHECKED: 'Đã kiểm tra mã băm bản ghi nguồn',
  H2B_ENVELOPE_SHA256: 'Đã đối chiếu SHA-256 của gói bản ghi nguồn',
  DIRECT_PERSISTED: 'Liên kết bằng chứng được bộ phát hiện lưu trực tiếp',
  PERSISTED_P17_SNAPSHOT: 'Bản chụp bằng chứng đã lưu của bộ phát hiện',
  'Proxy P17 via SSH': 'Bộ phát hiện hành vi · kết nối SSH tới Proxy',
  P17_G03_V3_SQLITE: 'Kho dữ liệu phân tích hành vi · SQLite',
  'Proxy systemd snapshot': 'Trạng thái dịch vụ trên Proxy',
  'Galera wsrep snapshots': 'Trạng thái sao chép cụm Galera',
  'Portal source status report': 'Tình trạng kết nối các nguồn dữ liệu',
  'p17-incident-durable-1': 'Bản ghi sự cố bền vững · phiên bản 1',
  'portal-p16h-live-1': 'Nhật ký kiểm toán chuẩn hóa · phiên bản 1',
  'portal-proxy-services-1': 'Trạng thái dịch vụ · phiên bản 1',
  'portal-galera-node-1': 'Trạng thái nút Galera · phiên bản 1',
  'openstack-inventory-1': 'Danh mục hạ tầng OpenStack · phiên bản 1',
  'n91-portal-p17-vnext-1': 'Phân tích hành vi và chuỗi sự kiện · phiên bản 1',
  'p17-lab-clone': 'attack',
  'n91-clone-auto-corr002-v2': 'Tự động cách ly máy thử nghiệm · CORR-002 · phiên bản 2',
  'p17-incident-g03-dual-v3-20261104': 'Bộ phát hiện hành vi · G03 · phiên bản 3 · 04/11/2026',
  'UNREVIEWED': 'Chưa rà soát', 'NONE': 'Chưa xử lý', 'VERIFIED_BEFORE': 'Đã xác minh trước thực thi',
  'ATTEMPTED': 'Đã bắt đầu thực thi',
  'db-firewall-p17.service': 'Bộ phát hiện hành vi · dịch vụ systemd',
  'db-firewall-audit-ingest.service': 'Thu thập nhật ký kiểm toán · dịch vụ systemd',
  Port: 'Port', Project: 'Project', Network: 'Network', 'Floating IP': 'Floating IP',
  'Compute host': 'Compute host', 'Revision Neutron': 'Revision (Neutron)',
  'Port Security': 'Port Security', 'Port status': 'Trạng thái Port',
  'Backend': 'Dịch vụ xử lý', 'Frontend': 'Giao diện', 'Snapshot': 'Bản chụp dữ liệu',
  VERIFIED_EQUAL: 'Mã băm khớp bản ghi nguồn',
  'P17 snapshot reader': 'Nguồn dữ liệu phân tích sự cố',
  'Proxy P17 SSH reader': 'Nguồn dữ liệu sự cố từ Proxy',
  'P17 worker live': 'Bộ phát hiện hành vi và sự cố',
  'P16H canonical reader': 'Bộ đọc nhật ký bảo mật',
  'P17.5 controller': 'Bộ điều khiển cách ly và khôi phục',
  'P17 snapshot': 'Bản ghi phân tích sự cố',
  'P16H canonical audit (independent source)': 'Nhật ký bảo mật chuẩn hóa',
  'P16H canonical audit': 'Nhật ký bảo mật chuẩn hóa',
  'P15 risk score': 'Điểm đánh giá rủi ro',
  'P15 cao trên một request': 'Điểm rủi ro cao trên một yêu cầu',
  'P17 tương quan SQL injection': 'Tương quan SQL injection',
  'P17 tương quan truy cập dữ liệu nhạy cảm': 'Truy cập dữ liệu nhạy cảm có tương quan',
  'Cảnh báo tương quan P17': 'Cảnh báo tương quan', 'Cảnh báo từ P17': 'Cảnh báo bảo mật',
  'LIVE SAFE': 'Trực tiếp có kiểm soát', 'LIVE / LAB': 'Trực tiếp / thử nghiệm',
  'LIVE + owner lab': 'Trực tiếp và thử nghiệm được cho phép', 'LAB controlled': 'Thử nghiệm có kiểm soát',
  'OFFLINE+LIVE': 'Ngoại tuyến và trực tiếp', 'MIXED LAB': 'Kết hợp trong môi trường thử nghiệm',
  'ISOLATED+LIVE': 'Môi trường riêng và trực tiếp', 'LIVE+ISOLATED': 'Trực tiếp và môi trường riêng',
  'LAB HISTORICAL': 'Kết quả thử nghiệm đã lưu',
  LIVE_READ_ONLY: 'Trực tiếp chỉ đọc', OFFLINE_POLICY: 'Chính sách ngoại tuyến',
  PROTOCOL_OFFLINE: 'Giao thức ngoại tuyến', P17_OFFLINE: 'Phát hiện sự cố ngoại tuyến',
  NOT_CAPTURED: 'Chưa ghi nhận',
  OPEN: 'Chưa khép lại', CLOSED: 'Đã khép lại', LAB: 'Thử nghiệm',
  Overview: 'Tổng quan', Parser: 'Phân tích cú pháp', Rules: 'Quy tắc', Risk: 'Rủi ro',
  Timeline: 'Dòng thời gian', Trace: 'Luồng xử lý', Evidence: 'Bằng chứng', Provenance: 'Nguồn gốc dữ liệu',
  'SQL requests / events': 'Yêu cầu / sự kiện SQL', 'SQL parse': 'Phân tích SQL',
  'ALLOW / BLOCK': 'Cho phép / Chặn', Alerts: 'Cảnh báo', Incidents: 'Sự cố', Actions: 'Xử lý',
  'request đã xác minh ID': 'yêu cầu có định danh', 'audit event': 'sự kiện kiểm toán',
  'parse valid': 'phân tích hợp lệ', 'parse invalid': 'phân tích không hợp lệ',
  alert: 'cảnh báo', 'incident mới': 'sự cố mới', action: 'hành động',
  REQUEST_ID_NOT_PROVIDED: 'Nguồn chưa cung cấp mã yêu cầu; chỉ đếm bản ghi kiểm toán.',
  PARSER_FEATURES_NOT_PROVIDED: 'Chưa có kết quả phân tích cú pháp.',
  IMPORTED_RECORDS_ONLY: 'Số bản ghi đã đọc; chưa xác nhận đầy đủ lưu lượng.',
  OUTBOX_RECORDS_ONLY: 'Số cảnh báo đã thu thập.',
  P17_CREATED_RECORDS_ONLY: 'Số sự cố được tạo trong khoảng thời gian đã chọn.',
  P17_5_NOT_CONFIGURED: 'Chưa có bằng chứng xử lý.',
  EVALUATION_FUNNEL_NOT_CAPTURED: 'Chưa có số liệu cho bước này trong lần đánh giá.',
  REQUEST: 'Yêu cầu', PARSE: 'Phân tích', POLICY: 'Chính sách', ALERT: 'Cảnh báo',
  INCIDENT: 'Sự cố', ACTION: 'Hành động', monitor: 'Giám sát', enforce: 'Thực thi',
  'HA / Resilience': 'Tính sẵn sàng và khả năng phục hồi',
  'Backup artifacts': 'Bản sao lưu', 'G07 recovery · LAB': 'Khôi phục · thử nghiệm',
  'Fault → verified query (LAB)': 'Từ sự cố đến truy vấn được xác minh · thử nghiệm',
  'Backup gap (LAB)': 'Khoảng cách sao lưu · thử nghiệm',
  'Fault → verified truy vấn (LAB)': 'Từ sự cố đến truy vấn được xác minh · thử nghiệm',
  'Lost marker count': 'Số mốc dữ liệu bị mất', 'Chỉ số scope': 'Phạm vi chỉ số',
  'Production measurement': 'Kết quả đo môi trường vận hành', 'Timing limitation': 'Giới hạn thời gian',
  'Committed markers': 'Mốc dữ liệu đã ghi', 'Restored markers': 'Mốc dữ liệu đã khôi phục', 'Lost markers': 'Mốc dữ liệu bị mất',
  backup_id: 'Mã bản sao lưu', source_node: 'Máy nguồn', backup_type: 'Loại sao lưu',
  sha256: 'SHA256', sha256_verified: 'SHA256 đã xác minh', size_bytes: 'Kích thước (byte)',
  restore_run_id: 'Mã lần khôi phục', target_name: 'Đích khôi phục', observation_kind: 'Loại quan sát',
  verification_state: 'Trạng thái xác minh', current_verification: 'Xác minh hiện tại', mariadb_status: 'Trạng thái MariaDB',
  resilience_id: 'Mã kiểm tra phục hồi', gate: 'Điều kiện nghiệm thu', scenario: 'Kịch bản',
  expected_outcome: 'Kết quả dự kiến', observed_outcome: 'Kết quả quan sát', verdict: 'Kết quả',
  route_id: 'Mã đường kết nối', source: 'Nguồn', destination: 'Đích', negotiated_version: 'Phiên bản đã thỏa thuận',
  peer_verified: 'Đối tác đã xác minh', status: 'Trạng thái', handshake_retry_limitation: 'Giới hạn thử lại kết nối',
  lab_scope_status: 'Trạng thái thử nghiệm', strict_ready: 'Đủ điều kiện nghiệm thu', authority: 'Căn cứ xác nhận',
  owner_attestation: 'Xác nhận của người phụ trách', ack_disposition: 'Tình trạng tiếp nhận', exceptions: 'Ngoại lệ',
  SANITIZED: 'Đã ẩn dữ liệu nhạy cảm', NOT_MEASURED: 'Chưa đo', NONE_CAPTURED: 'Chưa thu thập',
  'TLS negotiated bằng chứng': 'Bằng chứng kết nối TLS', 'Bảo vệ dữ liệu · bounded samples': 'Mẫu kiểm tra bảo vệ dữ liệu',
  'F01 / F02 staging': 'Kiểm thử giao thức', 'Nghiệm thu · strict readiness': 'Điều kiện nghiệm thu',
  NA: 'Không áp dụng', NOT_APPLICABLE: 'Không áp dụng', EMPTY: 'Không có dữ liệu',
  NOT_IMPORTED: 'Chưa nhập dữ liệu', REQUIRED: 'Bắt buộc', STRICT_READY: 'Đủ điều kiện nghiệm thu',
  SQL_REQUEST_RECORDED: 'Ghi nhận yêu cầu SQL', P17_INCIDENT_CREATED: 'Tạo sự cố',
  P17_INCIDENT_UPDATED: 'Cập nhật sự cố', P17_ALERT_RECORDED: 'Ghi nhận cảnh báo',
  P17_EVENT_PROJECTION: 'Thông tin sự kiện phát hiện', P16H_CANONICAL_AUDIT: 'Nhật ký kiểm toán chuẩn',
  SINGLE_P15_HIGH: 'Điểm rủi ro cao', CORRELATED: 'Có tương quan', OPERATIONAL: 'Vận hành',
  POLICY_VIOLATION: 'Vi phạm chính sách', AUDIT_HEALTH: 'Trạng thái kiểm toán',
  SYSTEM_HEALTH: 'Trạng thái hệ thống', OTHER: 'Khác', NOT_PROVIDED: 'Chưa cung cấp',
  UNKNOWN_SOURCE: 'Chưa xác định nguồn', PORTAL_ANNOTATION: 'Ghi chú của Portal',
  FRESH: 'Đã cập nhật', STALE: 'Chưa cập nhật', UNKNOWN: 'Chưa xác định',
  OUT_OF_ORDER: 'Đến sai thứ tự', FUTURE_SKEW: 'Thời điểm ở tương lai',
  UNAVAILABLE: 'Chưa có dữ liệu', PARTIAL: 'Chưa đầy đủ', AVAILABLE: 'Có dữ liệu',
  HISTORICAL: 'Lịch sử', SNAPSHOT: 'Bản chụp', LIVE: 'Trực tiếp',
  LIVE_LAB: 'Trực tiếp · thử nghiệm', HISTORICAL_LAB: 'Lịch sử · thử nghiệm',
  LIVE_PREFLIGHT: 'Kiểm tra trước vận hành', OFFLINE: 'Ngoại tuyến',
  ISOLATED: 'Môi trường riêng', STAGING: 'Môi trường kiểm thử', TEST: 'Thử nghiệm',
  IMPORTED_UNVERIFIED: 'Dữ liệu nhập chưa xác minh', EVALUATION: 'Đánh giá',
  DESIGN_ONLY: 'Mới có kế hoạch', EXPECTED: 'Dự kiến', OBSERVED: 'Đã quan sát',
  OBSERVATION: 'Chỉ đọc', SESSION: 'Phiên đăng nhập', READ_ONLY: 'Chỉ đọc',
  ALLOW: 'Cho phép', BLOCK: 'Chặn', FORWARDED: 'Đã chuyển tiếp', BLOCKED: 'Đã chặn',
  ERROR: 'Lỗi', FAILED: 'Thất bại', SUCCESS: 'Thành công', OK: 'Hợp lệ',
  PASS: 'Đạt', FAIL: 'Không đạt', NOT_RUN: 'Chưa chạy', NOT_EXECUTED: 'Chưa thực hiện',
  PENDING: 'Chờ xử lý', NOT_VERIFIED: 'Chưa xác minh', VERIFIED: 'Đã xác minh',
  UNVERIFIED: 'Chưa xác minh', INCOMPLETE: 'Chưa đầy đủ', COMPLETE: 'Đầy đủ',
  HEALTHY: 'Hoạt động tốt', DEGRADED: 'Suy giảm', DOWN: 'Ngừng hoạt động',
  ONLINE: 'Đang kết nối', OFFLINE_SOURCE: 'Mất kết nối', NORMAL: 'Bình thường',
  UNREACHABLE: 'Không kết nối được', REACHABLE: 'Kết nối được', WARNING: 'Cảnh báo',
  HIGH: 'Cao', MEDIUM: 'Trung bình', LOW: 'Thấp', CRITICAL: 'Nghiêm trọng',
  INFO: 'Thông tin', URGENT: 'Khẩn cấp', UNSET: 'Chưa đặt',
  ACTIVE: 'Đang hoạt động', SHUTOFF: 'Đã tắt', PAUSED: 'Tạm dừng', SUSPENDED: 'Tạm ngưng',
  BUILD: 'Đang tạo', SYNCED: 'Đã đồng bộ', Synced: 'Đã đồng bộ', Primary: 'Cụm chính', PRIMARY: 'Cụm chính',
  ON: 'Bật', OFF: 'Tắt', RUNNING: 'Đang chạy', STOPPED: 'Đã dừng',
  active: 'Đang hoạt động', running: 'Đang chạy', inactive: 'Không hoạt động', dead: 'Đã dừng',
  loaded: 'Đã nạp', success: 'Thành công', failed: 'Thất bại', exited: 'Đã kết thúc',
  QUARANTINED: 'Đang cách ly', RESTORED: 'Đã khôi phục', RECOVERY_REQUIRED: 'Cần khôi phục',
  REVIEW_REQUIRED: 'Cần rà soát', CANDIDATE_CORRELATED: 'Nghi vấn có tương quan',
  UNREAD: 'Chưa đọc', REVIEWED: 'Đã rà soát', ACK: 'Đã tiếp nhận', ACKNOWLEDGED: 'Đã tiếp nhận',
  MISMATCH: 'Không khớp', DRIFT: 'Có sai lệch', PENDING_VERIFICATION: 'Chờ xác minh',
  RECONSTRUCTED_WINDOW: 'Liên kết dựng lại theo cửa sổ thời gian',
  LEGACY_UNPINNED: 'Chưa xác định phiên bản bộ phát hiện',
  NOT_PROVEN: 'Chưa được chứng minh', DIRECT_SOURCE: 'Liên kết trực tiếp từ nguồn',
  SNAPSHOT_PROJECTION: 'Thông tin từ bản chụp', SNAPSHOT_RECORD: 'Bản ghi lịch sử',
  NOT_TRIGGERED: 'Không kích hoạt', WITHHELD: 'Đã ẩn', MASKED: 'Đã che nội dung',
  PRESENT: 'Đã cung cấp', RECONSTRUCTED: 'Được tái dựng', LOADING: 'Đang tải',
  ENABLED: 'Đã bật', DISABLED: 'Đã tắt', FEATURE_DISABLED: 'Chưa bật chức năng',
  BEFORE: 'Trước xử lý', DURING: 'Trong xử lý', AFTER: 'Sau xử lý', CURRENT: 'Hiện tại',
  Analyst: 'Chuyên viên phân tích', Operator: 'Người vận hành', Viewer: 'Người xem',
  Approver: 'Người phê duyệt', Executor: 'Người thực thi', Auditor: 'Người kiểm tra',
  SQL_PARSE: 'Phân tích SQL', P14_POLICY: 'Áp dụng chính sách', P15_RISK: 'Đánh giá rủi ro',
  P16H_AUDIT: 'Ghi nhật ký kiểm toán', P17_DETECTION: 'Phát hiện sự cố',
  P17_DECISION: 'Đánh giá điều kiện xử lý', P17_5_RESPONSE: 'Thực hiện xử lý',
  P17: 'Phát hiện sự cố', P16H: 'Nhật ký kiểm toán', P17_3: 'Điều kiện xử lý',
  CONTROLLER: 'Bộ điều khiển', DEFENSE_REGISTRY: 'Kho bằng chứng', PORTAL_BUSINESS: 'Ghi chú và rà soát',
  source_verified: 'Nguồn đã xác minh', isolation_authorized: 'Được phép cách ly',
  source_system: 'Nguồn dữ liệu', source_schema: 'Cấu trúc dữ liệu', source_ref: 'Tham chiếu nguồn',
  observed_at: 'Quan sát lúc', read_at: 'Đọc lúc', data_as_of: 'Dữ liệu đến',
  captured_at: 'Chụp lúc', imported_at: 'Nhập lúc', freshness_state: 'Tình trạng cập nhật',
  execution_mode: 'Chế độ thực hiện', verification: 'Mức xác minh', context: 'Phạm vi dữ liệu',
  source_verified_recorded: 'Nguồn đã xác minh', isolation_authorized_recorded: 'Được phép cách ly',
  'p17-proxy-reader': 'Nguồn sự cố từ Proxy', 'p17-snapshot': 'Bản ghi sự cố',
  'p16-canonical-audit': 'Nhật ký kiểm toán', 'P17 outbox': 'Nguồn cảnh báo bảo mật',
  'N91 defense source registry': 'Kho bằng chứng', 'P16H canonical': 'Nhật ký kiểm toán chuẩn',
  IMPORTED_OBSERVATION: 'Quan sát đã nhập', PLANNED: 'Đã lên kế hoạch',
  SOURCE_NOT_PROVIDED: 'Nguồn chưa cung cấp dữ liệu',
  DETECTOR_PROFILE_UNAVAILABLE: 'Thiếu phiên bản hoặc mã SHA256 của bộ phát hiện P17',
  DETECTOR_PROFILE_MISMATCH: 'Phiên bản hoặc mã SHA256 không khớp hồ sơ bộ phát hiện P17',
  DETECTOR_PROFILE_INCOMPLETE: 'Định danh khớp hồ sơ ngày 10/11, còn thiếu mã đầy đủ và căn cứ áp dụng cho sự cố',
  LEGACY_CANDIDATES_UNPINNED: 'Chưa xác định phiên bản bộ phát hiện',
  P17_3_DECISION_NOT_PROVIDED: 'Chưa có kết quả đánh giá điều kiện xử lý',
  CONTROLLER_SEMANTIC_PROJECTION_NOT_PROVIDED: 'Chưa có bằng chứng xử lý từ bộ điều khiển',
  P17_STREAM_UNVERIFIED: 'Chưa xác minh được cặp stream và incident từ P17',
  P17_BINDING_MISMATCH: 'Thông tin liên kết P17 không khớp nguồn Controller',
  P17_BINDING_UNAVAILABLE: 'Chưa đọc được thông tin liên kết P17 đã kiểm mã băm',
  CONTROLLER_HISTORY_STANDALONE: 'Lịch sử Controller được hiển thị riêng',
  CONTROLLER_HISTORY_SCOPE_AMBIGUOUS: 'Chưa xác định được phạm vi lịch sử Controller',
  CONTROLLER_MULTIPLE_CYCLES: 'Có nhiều lần xử lý. Chưa xác định trạng thái hiện tại theo lần xử lý',
  CONTROLLER_PROJECTION_INVALID: 'Dữ liệu lịch sử Controller chưa đúng định dạng',
  CONTROLLER_PROFILE_UNSUPPORTED: 'Chưa hỗ trợ định dạng bằng chứng Controller này',
  CONTROLLER_MANIFEST_INCIDENT_MISMATCH: 'Incident trong manifest và bản ghi Controller không khớp',
  CONTROLLER_CONTAINMENT_UTC: 'Mốc UTC do Controller ghi',
  CONTROLLER_CLOCK_BASIS_UNAVAILABLE: 'Chưa xác định được căn cứ thời gian của Controller',
  SG_CAPTURE_TIME_UNAVAILABLE: 'Thiếu thời điểm quan sát của snapshot Security Group',
  SG_DURING_IDENTITY_UNAVAILABLE: 'Mẫu trong cách ly thiếu định danh để xác nhận đúng port và máy ảo',
  SG_BEFORE_UNAVAILABLE: 'Chưa có snapshot trước cách ly',
  SG_AFTER_UNAVAILABLE: 'Chưa có snapshot sau khôi phục',
  SG_BEFORE_IDENTITY_MISMATCH: 'Snapshot trước cách ly sai định danh port hoặc máy ảo',
  SG_AFTER_IDENTITY_MISMATCH: 'Snapshot sau khôi phục sai định danh port hoặc máy ảo',
  SG_PROJECT_MISMATCH: 'Project của hai snapshot không khớp nhau',
  SG_RESTORE_MISMATCH: 'Tập Security Group sau xử lý khác tập gốc do Controller ghi',
  NEUTRON_CURRENT_UNAVAILABLE: 'Chưa đọc được quan sát hiện tại từ Neutron',
  NEUTRON_CURRENT_NOT_REQUESTED: 'Chưa yêu cầu đọc trạng thái hiện tại từ Neutron',
  NEUTRON_CURRENT_STALE: 'Quan sát Neutron đã hết hạn',
  NEUTRON_CURRENT_NOT_LIVE: 'Nguồn quan sát Neutron hiện tại chưa được xác nhận',
  NEUTRON_IDENTITY_MISMATCH: 'Quan sát Neutron không khớp port, máy ảo hoặc project',
  NEUTRON_PORT_AMBIGUOUS: 'Không xác định được một port duy nhất trong Neutron',
  NEUTRON_TARGET_IDENTITY_UNAVAILABLE: 'Thiếu định danh project của port lịch sử',
  NEUTRON_BASELINE_UNAVAILABLE: 'Thiếu tập Security Group gốc để đối chiếu',
  RESPONSE_STATE_MISMATCH: 'Tập Security Group hiện tại khác tập gốc đã khôi phục',
  MISSING_CLOCK_MARK: 'Chưa có đủ hai mốc thời gian',
  AMBIGUOUS_CLOCK_MARK: 'Có nhiều mốc thời gian ứng viên',
  INCIDENT_CYCLE_MISMATCH: 'Hai mốc thuộc các lần xử lý khác nhau',
  CLOCK_TIME_BASIS_MISMATCH: 'Hai mốc khác căn cứ thời gian',
  NEGATIVE_DURATION: 'Thứ tự hai mốc thời gian không hợp lệ',
  CONTAINMENT: 'Bản ghi cách ly và khôi phục',
  CLONE_BEFORE: 'Snapshot port trước cách ly',
  CLONE_AFTER: 'Snapshot port sau khôi phục',
  SG_SAMPLER: 'Mẫu Security Group',
  CONTROLLER_WATCH: 'Theo dõi Controller',
  RESTORE_VERIFICATION: 'Đối chiếu khôi phục',
  OBSERVATION_READ_ONLY: 'Chế độ chỉ đọc', DIRECT_MEMBERSHIP_NOT_PROVIDED: 'Nguồn chưa cung cấp liên kết trực tiếp',
  LEGACY_DETECTOR_PROFILE_UNPINNED: 'Chưa xác định phiên bản bộ phát hiện',
  CANONICAL_SOURCE_UNAVAILABLE: 'Chưa đọc được nhật ký kiểm toán', CANONICAL_RECORD_NOT_FOUND: 'Chưa tìm thấy bản ghi kiểm toán tương ứng',
  PAYLOAD_HASH_BASIS_NOT_PROVEN: 'Chưa đủ căn cứ đối chiếu mã băm nội dung',
  CONTENT_REVIEW_REQUIRED: 'Cần rà soát nội dung', TIMESTAMP_UNAVAILABLE: 'Chưa có thời điểm nguồn',
  HOST_BUNDLE_MISSING: 'Thiếu dữ liệu của máy nguồn', DATA_AS_OF_NOT_PROVIDED: 'Nguồn chưa công bố mốc dữ liệu',
  OBSERVATION_TIME_NOT_PROVIDED: 'Nguồn chưa cung cấp thời điểm quan sát',
}

export function uiLabel(value) {
  if (value === null || value === undefined || value === '') return 'Chưa xác định'
  if (typeof value === 'boolean') return value ? 'Có' : 'Không'
  const key = String(value)
  return uiText(Object.hasOwn(valueLabels, key) ? valueLabels[key]
    : Object.hasOwn(labels, key.trim()) ? labels[key.trim()]
      : Object.hasOwn(normalizedFields, key.trim().toLowerCase()) ? normalizedFields[key.trim().toLowerCase()] : key)
}

export function uiErrorMessage(error) {
  return sourceErrors[error?.code] || uiText(error?.message || 'Chưa đọc được nguồn dữ liệu.')
}

// Display copy only. API keys, source objects, URLs and exported evidence stay original.
export function uiText(value) {
  if (typeof value !== 'string') return value
  if (/^\s*(SELECT|WITH|GRANT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)\s/i.test(value)) return value
  let result = value.replace(/\bP17[._]5\b/gi, 'bộ điều khiển phản ứng')
    .replace(/\bP17[._]3\b/gi, 'bộ đánh giá điều kiện xử lý')
    .replace(/\bP16H\b/gi, 'nhật ký kiểm toán chuẩn hóa')
    .replace(/\bP17\b/gi, 'bộ phát hiện hành vi')
    .replace(/\bP16\b/gi, 'API quản trị bảo mật')
    .replace(/\bP15\b/gi, 'bộ đánh giá rủi ro')
    .replace(/\bP14\b/gi, 'bộ thực thi chính sách')
    .replace(/\bP19\b/gi, 'bộ kiểm thử nghiệm thu')
  if (/\s/.test(result)) result = result
    .replace(/\bCanonical(?: Audit)?\b/gi, 'nhật ký kiểm toán chuẩn hóa')
    .replace(/\bsnapshot\b/gi, 'bản chụp')
    .replace(/\bController\b/g, 'bộ điều khiển')
    .replace(/\bworker\b/gi, 'bộ xử lý phát hiện')
    .replace(/\bhash\b/gi, 'mã băm')
    .replace(/\brequest\b/g, 'yêu cầu')
    .replace(/\bincident\b/gi, 'sự cố')
    .replace(/\bstream\b/g, 'luồng dữ liệu')
    .replace(/\bEvent\b/g, 'sự kiện')
    .replace(/\bupstream\b/gi, 'nguồn gốc')
    .replace(/\bmetadata\b/gi, 'thông tin mô tả')
    .replace(/\benvelope\b/gi, 'gói bản ghi')
    .replace(/\bproduction\b/gi, 'môi trường vận hành')
    .replace(/\bLAB\b/g, 'thử nghiệm')
    .replace(/\blab\b/g, 'môi trường thử nghiệm')
    .replace(/bộ phát hiện bộ phát hiện hành vi/g, 'bộ phát hiện hành vi')
  return result
}

export function uiRoleList(value) {
  return typeof value === 'string' ? value.split(',').map((role) => uiLabel(role.trim())).join(', ') : uiLabel(value)
}

// Copy generated by the alert adapter, localized only where it is displayed.
export function uiAlertSummary(value) {
  if (typeof value !== 'string') return ''
  if (value === 'P17 ghi cảnh báo P15 cao cho một request; chưa tự chứng minh có incident tương quan.')
    return 'Điểm rủi ro cao trên một yêu cầu; chưa xác nhận có sự cố tương quan.'
  return value.replace(/^P17 ghi signal /, 'Tín hiệu được ghi nhận: ')
    .replace('Số request evidence theo alert:', 'Số yêu cầu làm bằng chứng theo cảnh báo:')
}
