-- get_car_by_vin.sql
SELECT vin, maker, model, year, trim, listed_at
FROM cars
WHERE vin = :vin
LIMIT 1;