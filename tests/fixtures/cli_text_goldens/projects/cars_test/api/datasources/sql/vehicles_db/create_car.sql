-- create_car.sql
-- A write script is just a function/procedure call that returns a result
-- set, same contract as any SELECT — insert_car does the actual
-- INSERT ... RETURNING internally.
SELECT * FROM insert_car(:maker, :model, :year);
