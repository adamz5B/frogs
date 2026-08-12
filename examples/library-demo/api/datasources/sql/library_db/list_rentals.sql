SELECT
  r.id,
  r.book_id,
  b.title AS book_title,
  r.member_id,
  m.name AS member_name,
  r.checked_out_at,
  r.due_at,
  r.returned_at
FROM rentals r
JOIN books b ON b.id = r.book_id
JOIN members m ON m.id = r.member_id
ORDER BY r.checked_out_at DESC;
