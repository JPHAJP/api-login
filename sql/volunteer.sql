CREATE EXTENSION IF NOT EXISTS tablefunc;


--
-- Volunteer schema creation
--
DROP SCHEMA IF EXISTS volunteer CASCADE;
CREATE SCHEMA IF NOT EXISTS volunteer;

--
-- Datatypes creation
--
DROP TYPE IF EXISTS volunteer.gender CASCADE;
CREATE TYPE volunteer.gender AS ENUM (
    'mujer',
    'hombre'
    );
COMMENT ON TYPE volunteer.gender IS $comment$Volunteer gender$comment$;

DROP TYPE IF EXISTS volunteer.status CASCADE;
CREATE TYPE volunteer.status AS ENUM (
    'active',
    'inactive',
    'rejected'
    );
COMMENT ON TYPE volunteer.status IS $comment$Volunteer status$comment$;

DROP TYPE IF EXISTS volunteer.area CASCADE;
CREATE TYPE volunteer.area AS ENUM (
    'administracion',
    'bazar',
    'cocina',
    'lactantes',
    'mantenimiento',
    'maternal',
    'preescolar',
    'procuracion'
    );
COMMENT ON TYPE volunteer.area IS $comment$Volunteer area$comment$;

DROP TYPE IF EXISTS volunteer.workday CASCADE;
CREATE TYPE volunteer.workday AS ENUM (
    'monday',
    'tuesday',
    'wednesday',
    'thursday',
    'friday',
    'saturday',
    'sunday'
    );
COMMENT ON TYPE volunteer.workday IS $comment$Volunteer work day$comment$;

DROP TYPE IF EXISTS volunteer.document_type CASCADE;
CREATE TYPE volunteer.document_type AS ENUM (
    'official_id_elec',
    'official_id_physical',
    'domicilio_electronic',
    'domicilio_physical',
    'COVID_vaccine_electronic',
    'COVID_vaccine_physical',
    'recomendation_electronic',
    'recomendation_physical',
    'manual_electronic',
    'manual_physical',
    'medical_form_electronic',
    'medical_form_physical',
    'engagement_card_electronic',
    'engagement_card_physical',
    'volunteer_entry_form_electronic',
    'volunteer_entry_form_physical',
    'criminal_record_cert_electronic',
    'criminal_record_cert_physical',
    'fotos_electronic',
    'fotos_physical'
    );
COMMENT ON TYPE volunteer.document_type IS $comment$Volunteer document type$comment$;

DROP TYPE IF EXISTS volunteer.document_status CASCADE;
CREATE TYPE volunteer.document_status AS ENUM (
    'pending',
    'received',
    'archived'
    );
COMMENT ON TYPE volunteer.document_status IS $comment$Volunteer document status$comment$;

DROP TYPE IF EXISTS volunteer.meeting_type CASCADE;
CREATE TYPE volunteer.meeting_type AS ENUM (
    'interest',
    'call',
    'interview_planning',
    'interview',
    'introduction'
    );
COMMENT ON TYPE volunteer.meeting_type IS $comment$Volunteer document meeting type$comment$;


DROP TYPE IF EXISTS volunteer.meeting_status CASCADE;
CREATE TYPE volunteer.meeting_status AS ENUM (
    'pending',
    'done'
    );
COMMENT ON TYPE volunteer.meeting_status IS $comment$Volunteer meeting status$comment$;

DROP TYPE IF EXISTS volunteer.material_type CASCADE;
CREATE TYPE volunteer.material_type AS ENUM (
    'uniform',
    'badge'
    );
COMMENT ON TYPE volunteer.material_type IS $comment$Volunteer document material type$comment$;

DROP TYPE IF EXISTS volunteer.material_status CASCADE;
CREATE TYPE volunteer.material_status AS ENUM (
    'pending',
    'paid',
    'ready',
    'distributed'
    );
COMMENT ON TYPE volunteer.material_status IS $comment$Volunteer material status$comment$;

--
-- Tables creation
--
DROP TABLE IF EXISTS volunteer.volunteer;
CREATE TABLE IF NOT EXISTS volunteer.volunteer
(
    id         SERIAL PRIMARY KEY,
    email      VARCHAR(120) UNIQUE NOT NULL,
    name       VARCHAR(50) NOT NULL,
    surname    VARCHAR(50) NOT NULL,
    birthdate  DATE,
    gender     volunteer.gender DEFAULT 'mujer'::volunteer.GENDER,
    phone      TEXT,
    address    VARCHAR( 255),
    occupacion TEXT,
    joined     DATE,
    status     volunteer.status DEFAULT 'inactive'::volunteer.status,
    created_at    TIMESTAMP        DEFAULT NOW(),
    updated_at    TIMESTAMP        DEFAULT NOW()
);
COMMENT ON TABLE volunteer.volunteer IS $comment$Volunteer personal data$comment$;

/*DROP TABLE IF EXISTS volunteer.area;
CREATE TABLE IF NOT EXISTS volunteer.area
(
    id SERIAL PRIMARY KEY,
    name ENUM( 'administracion', 'bazar', 'cocina', 'lactantes', 'mantenimiento', 'maternal', 'preescolar', 'procuracion'),
    created_at TIMESTAMP DEFAULT NOW()
);*/

DROP TABLE IF EXISTS volunteer.volunteer_area_lookup;
CREATE TABLE IF NOT EXISTS volunteer.volunteer_area_lookup
(
    id           SERIAL PRIMARY KEY,
    volunteer_id INT REFERENCES volunteer.volunteer (id),
    area_id      volunteer.area NOT NULL,
    start_date   DATE           NOT NULL,
    end_date     DATE           NOT NULL,
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);
COMMENT ON TABLE volunteer.volunteer_area_lookup IS $comment$Volunteer area affectation$comment$;

DROP TABLE IF EXISTS volunteer.work_plan;
CREATE TABLE IF NOT EXISTS volunteer.work_plan
(
    id         SERIAL PRIMARY KEY,
    day        volunteer.workday NOT NULL,
    hour_start TEXT,
    hour_end   TEXT,
    created_at    TIMESTAMP DEFAULT NOW(),
    updated_at    TIMESTAMP DEFAULT NOW()
);
COMMENT ON TABLE volunteer.work_plan IS $comment$Volunteer work planing$comment$;

DROP TABLE IF EXISTS volunteer.document;
CREATE TABLE IF NOT EXISTS volunteer.document
(
    id           SERIAL PRIMARY KEY,
    volunteer_id INT REFERENCES volunteer.volunteer (id),
    doc_type     volunteer.document_type NOT NULL,
    doc_status   volunteer.document_status DEFAULT 'pending'::volunteer.document_status,
    created_at      TIMESTAMP                 DEFAULT NOW(),
    updated_at      TIMESTAMP                 DEFAULT NOW()

);
COMMENT ON TABLE volunteer.document IS $comment$Volunteer mandatory documents$comment$;

DROP TABLE IF EXISTS volunteer.meeting;
CREATE TABLE IF NOT EXISTS volunteer.meeting
(
    id             SERIAL PRIMARY KEY,
    volunteer_id   INT REFERENCES volunteer.volunteer (id),
    meeting_type   volunteer.meeting_type   DEFAULT 'interest'::volunteer.meeting_type,
    meeting_status volunteer.meeting_status DEFAULT 'pending'::volunteer.meeting_status,
    created_at        TIMESTAMP                DEFAULT NOW(),
    updated_at        TIMESTAMP                DEFAULT NOW()
);
COMMENT ON TABLE volunteer.meeting IS $comment$Volunteer recruitments meetings$comment$;

DROP TABLE IF EXISTS volunteer.material;
CREATE TABLE IF NOT EXISTS volunteer.material
(
    id              SERIAL PRIMARY KEY,
    volunteer_id    INT REFERENCES volunteer.volunteer (id),
    material_type   volunteer.material_type   DEFAULT 'badge'::volunteer.material_type,
    material_status volunteer.material_status DEFAULT 'pending'::volunteer.material_status,
    created_at         TIMESTAMP                 DEFAULT NOW(),
    updated_at         TIMESTAMP                 DEFAULT NOW()
);
COMMENT ON TABLE volunteer.material IS $comment$Volunteer personal data$comment$;

--
-- Trigger functions definition
--

-- Documents
CREATE OR REPLACE FUNCTION volunteer.add_volunteer_docs()
    RETURNS TRIGGER AS $$
DECLARE
    v_enum_value   TEXT;
BEGIN

    FOR v_enum_value IN SELECT UNNEST(ENUM_RANGE(NULL::volunteer.document_type))
        LOOP
            INSERT INTO volunteer.document(volunteer_id, doc_type)
            VALUES (NEW.id, v_enum_value::volunteer.document_type);
        END LOOP;

    RETURN NEW;

END;
$$ LANGUAGE plpgsql;
COMMENT ON FUNCTION volunteer.add_volunteer_docs IS $comment$Adds list of mandatory documents for new volunteer$comment$;

CREATE TRIGGER after_volunteer_insert_docs
    AFTER INSERT ON volunteer.volunteer
    FOR EACH ROW
EXECUTE FUNCTION volunteer.add_volunteer_docs();

-- Meetings
CREATE OR REPLACE FUNCTION volunteer.add_volunteer_meetings()
    RETURNS TRIGGER AS $$
DECLARE
    v_enum_value   TEXT;
BEGIN

    FOR v_enum_value IN SELECT UNNEST(ENUM_RANGE(NULL::volunteer.meeting_type))
        LOOP
            INSERT INTO volunteer.meeting(volunteer_id, meeting_type)
            VALUES (NEW.id, v_enum_value::volunteer.meeting_type);
        END LOOP;

    RETURN NEW;

END;
$$ LANGUAGE plpgsql;
COMMENT ON FUNCTION volunteer.add_volunteer_meetings IS $comment$Adds list of mandatory documents for new volunteer$comment$;

CREATE TRIGGER after_volunteer_insert_meetings
    AFTER INSERT ON volunteer.volunteer
    FOR EACH ROW
EXECUTE FUNCTION volunteer.add_volunteer_meetings();

-- Material
CREATE OR REPLACE FUNCTION volunteer.add_volunteer_material()
    RETURNS TRIGGER AS $$
DECLARE
    v_enum_value   TEXT;
BEGIN

    FOR v_enum_value IN SELECT UNNEST(ENUM_RANGE(NULL::volunteer.material_type))
        LOOP
            INSERT INTO volunteer.material(volunteer_id, material_type)
            VALUES (NEW.id, v_enum_value::volunteer.material_type);
        END LOOP;

    RETURN NEW;

END;
$$ LANGUAGE plpgsql;
COMMENT ON FUNCTION volunteer.add_volunteer_material IS $comment$Adds list of mandatory documents for new volunteer$comment$;

CREATE TRIGGER after_volunteer_insert_material
    AFTER INSERT ON volunteer.volunteer
    FOR EACH ROW
EXECUTE FUNCTION volunteer.add_volunteer_material();

--
-- Views definition
--

-- Documents
CREATE OR REPLACE VIEW volunteer.volunteer_document_overview AS
SELECT *
FROM CROSSTAB(
             $query$
                    SELECT vd.volunteer_id, vd.doc_type, vd.doc_status
                    FROM volunteer.document vd
                    ORDER BY 1,2
                 $query$,
             $query$
                    SELECT doc_name::TEXT FROM UNNEST( ENUM_RANGE(NULL::volunteer.document_type)) AS data(doc_name) ORDER BY doc_name;
                 $query$)
         AS ct (
                volunteer_id INT,
                official_id_elec volunteer.document_status,
                official_id_physical volunteer.document_status,
                domicilio_electronic volunteer.document_status,
                domicilio_physical volunteer.document_status,
                COVID_vaccine_electronic volunteer.document_status,
                COVID_vaccine_physical volunteer.document_status,
                recomendation_electronic volunteer.document_status,
                recomendation_physical volunteer.document_status,
                manual_electronic volunteer.document_status,
                manual_physical volunteer.document_status,
                medical_form_electronic volunteer.document_status,
                medical_form_physical volunteer.document_status,
                engagement_card_electronic volunteer.document_status,
                engagement_card_physical volunteer.document_status,
                volunteer_entry_form_electronic volunteer.document_status,
                volunteer_entry_form_physical volunteer.document_status,
                criminal_record_cert_electronic volunteer.document_status,
                criminal_record_cert_physical volunteer.document_status,
                fotos_electronic volunteer.document_status,
                fotos_physical volunteer.document_status
        );
COMMENT ON VIEW volunteer.volunteer_document_overview IS $comment$Volunteer documents status overview$comment$;

-- Material
CREATE OR REPLACE VIEW volunteer.volunteer_material_overview AS
SELECT *
FROM CROSSTAB(
             $query$
                    SELECT vm.volunteer_id, vm.material_type, vm.material_status
                    FROM volunteer.material vm
                    ORDER BY 1,2
                 $query$,
             $query$
                    SELECT material_name::TEXT FROM UNNEST( ENUM_RANGE(NULL::volunteer.material_type)) AS data(material_name) ORDER BY material_name;
                 $query$)
         AS ct (
                volunteer_id INT,
                badge volunteer.material_status,
                uniform volunteer.material_status

        );
COMMENT ON VIEW volunteer.volunteer_material_overview IS $comment$Volunteer material status overview$comment$;

-- Meetings
CREATE OR REPLACE VIEW volunteer.volunteer_meeting_overview AS
SELECT *
FROM CROSSTAB(
             $query$
                    SELECT vm.volunteer_id, vm.meeting_type, vm.meeting_status
                    FROM volunteer.meeting vm
                    ORDER BY 1,2
                 $query$,
             $query$
                    SELECT meeting_name::TEXT FROM UNNEST( ENUM_RANGE(NULL::volunteer.meeting_type)) AS data(meeting_name) ORDER BY meeting_name;
                 $query$)
         AS ct (
                volunteer_id INT,
                call volunteer.meeting_status,
                interest volunteer.meeting_status,
                interview volunteer.meeting_status,
                interview_planning volunteer.meeting_status,
                introduction volunteer.meeting_status
        );
COMMENT ON VIEW volunteer.volunteer_meeting_overview IS $comment$Volunteer meeting status overview$comment$;

-- Full volunteer data overview
CREATE MATERIALIZED VIEW volunteer.full_volunteer_overview AS
SELECT
    vv.id,
    vv.email,
    vv.name,
    vv.surname,
    vv.birthdate,
    vv.gender,
    vv.phone,
    vv.address,
    vv.occupacion,
    vv.joined,
    vv.status,
    vv.created_at,
    vv.updated_at,
    vv_meeting_o.call,
    vv_meeting_o.interest,
    vv_meeting_o.interview_planning,
    vv_meeting_o.interview,
    vv_meeting_o.introduction,
    vvdo.official_id_elec,
    vvdo.official_id_physical,
    vvdo.domicilio_electronic,
    vvdo.domicilio_physical,
    vvdo.COVID_vaccine_electronic,
    vvdo.COVID_vaccine_physical,
    vvdo.recomendation_electronic,
    vvdo.recomendation_physical,
    vvdo.manual_electronic,
    vvdo.manual_physical,
    vvdo.medical_form_electronic,
    vvdo.medical_form_physical,
    vvdo.engagement_card_electronic,
    vvdo.engagement_card_physical,
    vvdo.volunteer_entry_form_electronic,
    vvdo.volunteer_entry_form_physical,
    vvdo.criminal_record_cert_electronic,
    vvdo.criminal_record_cert_physical,
    vvdo.fotos_electronic,
    vvdo.fotos_physical,
    vv_mat_o.uniform,
    vv_mat_o.badge
FROM
    volunteer.volunteer vv
        LEFT JOIN volunteer.volunteer_meeting_overview vv_meeting_o ON vv.id = vv_meeting_o.volunteer_id
        LEFT JOIN volunteer.volunteer_document_overview vvdo ON vv.id = vvdo.volunteer_id
        LEFT JOIN volunteer.volunteer_material_overview vv_mat_o ON vv.id = vv_mat_o.volunteer_id;
COMMENT ON VIEW volunteer.volunteer_meeting_overview IS $comment$Volunteer meeting status overview$comment$;

-- Full overview refresh triggers definitions
CREATE OR REPLACE FUNCTION volunteer.refresh_volunteer_matview()
    RETURNS TRIGGER AS $$
BEGIN
    REFRESH MATERIALIZED VIEW volunteer.full_volunteer_overview;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
COMMENT ON FUNCTION volunteer.refresh_volunteer_matview IS $comment$Refreshes materialized view for volunteer statuses overview$comment$;

-- Volunteer
CREATE TRIGGER after_volunteer_insert_refresh_matview
    AFTER INSERT ON volunteer.volunteer
    FOR EACH STATEMENT
EXECUTE FUNCTION volunteer.refresh_volunteer_matview();

CREATE TRIGGER after_volunteer_update_refresh_matview
    AFTER UPDATE ON volunteer.volunteer
    FOR EACH STATEMENT
EXECUTE FUNCTION volunteer.refresh_volunteer_matview();

-- Documents
CREATE TRIGGER after_document_update_refresh_matview
    AFTER UPDATE ON volunteer.document
    FOR EACH STATEMENT
EXECUTE FUNCTION volunteer.refresh_volunteer_matview();

-- Material
CREATE TRIGGER after_material_update_refresh_matview
    AFTER UPDATE ON volunteer.material
    FOR EACH STATEMENT
EXECUTE FUNCTION volunteer.refresh_volunteer_matview();

-- Meeting
CREATE TRIGGER after_meeting_update_refresh_matview
    AFTER UPDATE ON volunteer.meeting
    FOR EACH STATEMENT
EXECUTE FUNCTION volunteer.refresh_volunteer_matview();

--
-- Dummy data insertion
--
INSERT INTO volunteer.volunteer (email, name, surname, birthdate, gender, phone, occupacion, joined)
VALUES
    ('josepabloha@live.com.mx', 'Jose Pablo', 'Hernández Alono', TO_DATE('01-01-1995', 'DD-MM-YYYY'),
     'hombre'::volunteer.GENDER, '0000000000', 'estudiante', NOW());

INSERT INTO volunteer.volunteer (email, name, surname, birthdate, gender, phone, occupacion, joined)
VALUES
    ('josepabloha2@live.com.mx', 'Jose Pablo2', 'Hernández Alono2', TO_DATE('01-01-1995', 'DD-MM-YYYY'),
     'hombre'::volunteer.GENDER, '0000000002', 'estudiante', NOW()),
    ('josepabloha3@live.com.mx', 'Jose Pablo3', 'Hernández Alono3', TO_DATE('01-01-1995', 'DD-MM-YYYY'),
     'hombre'::volunteer.GENDER, '0000000003', 'estudiante', NOW());



INSERT INTO volunteer.volunteer (email, name, surname, birthdate, gender, phone, occupacion, joined)
VALUES
    ('josepabloha4@live.com.mx', 'Jose Pablo4', 'Hernández Alono4', TO_DATE('01-01-1995', 'DD-MM-YYYY'),
     'hombre'::volunteer.GENDER, '0000000004', 'estudiante', NOW());

