// Display copy for the checked-in plan. Does not alter source observations.
const scenes = {
  'SC-01': ['Sơ đồ và trạng thái hệ thống', 'Kiểm tra sơ đồ kết nối, dịch vụ và Galera theo nguồn và thời điểm quan sát.', 'Hệ thống / Máy ảo'],
  'SC-02': ['Truy vấn SQL hợp lệ', 'Kiểm tra truy vấn được cho phép theo quy tắc, điểm rủi ro và kết quả xử lý từ nguồn.', 'Sự kiện / Trang chủ'],
  'SC-03': ['Máy sao chép sai phạm vi', 'Kiểm tra quy tắc CTX-006 chặn truy vấn và đối chiếu ảnh hưởng đến máy ứng dụng.', 'So sánh sự kiện'],
  'SC-04': ['Một truy vấn SQL injection', 'Hiển thị quy tắc khớp, kết quả chặn, nội dung đã che và cảnh báo nếu nguồn cung cấp.', 'Sự kiện / Cảnh báo'],
  'SC-05': ['Tương quan ba yêu cầu SQL injection', 'Đối chiếu các yêu cầu riêng biệt, bằng chứng sự cố và độ tin cậy theo quy tắc CORR-002.', 'Chi tiết sự cố'],
  'SC-06': ['Điều kiện xử lý sự cố', 'Giữ thông tin xác minh nguồn và quyền cách ly theo bản ghi; việc cho phép thử nghiệm được theo dõi riêng.', 'Sự cố / Điều kiện xử lý'],
  'SC-07': ['Cách ly bằng Security Group', 'Đối chiếu Security Group trước và trong xử lý, đúng port của máy thử nghiệm và thời điểm nguồn quan sát.', 'Máy ảo / Security Group'],
  'SC-08': ['Tự động khôi phục', 'Đối chiếu kết quả khôi phục, Security Group trước và sau, cùng các kiểm tra từ bằng chứng.', 'Máy ảo / Dòng thời gian sự cố'],
  'SC-09': ['Danh mục 40 quy tắc', 'Đối chiếu phiên bản, mã băm, chế độ thực thi hoặc giám sát và bằng chứng của các quy tắc.', 'Hệ thống / Quy tắc'],
  'SC-10': ['Bộ 60 ca kiểm thử', 'Kế hoạch gồm 18 ca trực tiếp, 32 ca chính sách ngoại tuyến, 3 ca giao thức và 7 ca API sự cố; không phải 60 yêu cầu trực tiếp.', 'Hệ thống / Đánh giá'],
  'SC-11': ['Bộ 13 kịch bản tương quan', 'So sánh kết quả dự kiến và quan sát của 13 kịch bản trong môi trường riêng; không tính thành sự cố vận hành mới.', 'Hệ thống / Đánh giá'],
  'SC-12': ['Bảo vệ nội dung nhật ký', 'Đối chiếu việc che dữ liệu, mẫu kiểm tra và nguồn gốc nhật ký trong phạm vi đã đọc; không công bố SQL gốc.', 'Hệ thống / Bảo vệ dữ liệu'],
  'SC-13': ['TLS và tính sẵn sàng của Galera', 'Phân biệt trạng thái bản chụp, phiên TLS và chuyển đổi dự phòng trong môi trường riêng.', 'Hệ thống / Galera và TLS'],
  'SC-14': ['Khôi phục dữ liệu', 'Đối chiếu mã băm, mốc dữ liệu đã ghi, đã khôi phục hoặc bị mất và chỉ số thử nghiệm; chưa có kết quả đo môi trường vận hành.', 'Hệ thống / Sao lưu và khôi phục'],
  'SC-15': ['Kiểm thử giao thức', 'Trình bày bằng chứng trong môi trường kiểm thử; các kiểm tra trực tiếp và tình trạng môi trường vận hành giữ theo nguồn.', 'Hệ thống / Khả năng phục hồi'],
  'SC-16': ['Điều kiện nghiệm thu', 'Đọc kết quả nghiệm thu riêng; thiếu nguồn giữ trạng thái chưa xác định, không tự kết luận đạt.', 'Hệ thống / Nghiệm thu'],
}

export function demoSceneLabel(scenarioId, field, fallback) {
  const index = { title: 0, expected_outcome: 1, portal_section: 2 }[field]
  return Object.hasOwn(scenes, scenarioId) && Number.isInteger(index)
    ? scenes[scenarioId][index]
    : fallback
}
