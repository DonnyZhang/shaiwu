CREATE TABLE  `test`.`ts_brand` (
`id` INT NOT NULL AUTO_INCREMENT ,
`name` VARCHAR( 255 ) NOT NULL ,
`sname` VARCHAR( 255 ) NOT NULL ,
`logo` VARCHAR( 255 ) NOT NULL ,
`memo` TEXT NOT NULL ,
PRIMARY KEY (  `id` )
) ENGINE = MYISAM COMMENT =  '品牌库';