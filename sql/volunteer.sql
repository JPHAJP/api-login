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

DROP TYPE IF EXISTS volunteer.timesheet_status CASCADE;
CREATE TYPE volunteer.timesheet_status AS ENUM (
    'active',
    'inactive'
    );
COMMENT ON TYPE volunteer.timesheet_status IS $comment$Volunteer timesheet_status$comment$;

DROP TYPE IF EXISTS volunteer.area_name CASCADE;
CREATE TYPE volunteer.area_name AS ENUM (
    'administracion',
    'bazar',
    'cocina',
    'lactantes',
    'mantenimiento',
    'maternal',
    'preescolar',
    'procuracion'
    );
COMMENT ON TYPE volunteer.area_name IS $comment$Volunteer area_name$comment$;

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
CREATE MATERIALIZED VIEW volunteer.volunteer_recruitment_overview AS
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
COMMENT ON MATERIALIZED VIEW volunteer.volunteer_recruitment_overview IS $comment$Volunteer recruitment full overview$comment$;

-- Full overview refresh triggers definitions
CREATE OR REPLACE FUNCTION volunteer.refresh_volunteer_matview()
    RETURNS TRIGGER AS $$
BEGIN
    REFRESH MATERIALIZED VIEW volunteer.volunteer_recruitment_overview;
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

--
-- Workplan management
--

-- Area
DROP TABLE IF EXISTS volunteer.area;
CREATE TABLE IF NOT EXISTS volunteer.area
(
    id SERIAL PRIMARY KEY,
    area_name volunteer.area_name NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Volunteer_area_lookup
DROP TABLE IF EXISTS volunteer.volunteer_area_lookup;
CREATE TABLE IF NOT EXISTS volunteer.volunteer_area_lookup
(
    id           SERIAL PRIMARY KEY,
    volunteer_id INT REFERENCES volunteer.volunteer (id) NOT NULL,
    area_id      INT REFERENCES volunteer.area (id) NOT NULL,
    date_start   DATE DEFAULT CURRENT_DATE,
    date_end     DATE,
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);
COMMENT ON TABLE volunteer.volunteer_area_lookup IS $comment$Volunteer area affectation$comment$;

-- Timesheet
DROP TABLE IF EXISTS volunteer.timesheet;
CREATE TABLE IF NOT EXISTS volunteer.timesheet
(
    id           SERIAL PRIMARY KEY,
    volunteer_id INT     NOT NULL REFERENCES volunteer.volunteer (id),
    status       volunteer.timesheet_status NOT NULL DEFAULT 'active'::volunteer.timesheet_status,
    date_start   DATE DEFAULT CURRENT_DATE,
    date_end     DATE,
    description  TEXT,
    created_at   TIMESTAMP        DEFAULT NOW(),
    updated_at   TIMESTAMP        DEFAULT NOW()
);
COMMENT ON TABLE volunteer.timesheet IS $comment$Volunteer weekly timesheet$comment$;

-- Timesheet detail
DROP TABLE IF EXISTS volunteer.timesheet_detail;
CREATE TABLE IF NOT EXISTS volunteer.timesheet_detail
(
    id           SERIAL PRIMARY KEY,
    timesheet_id INT                        NOT NULL,
    workday      volunteer.workday          NOT NULL,
    hour_start   TIME                       NOT NULL,
    hour_end     TIME                       NOT NULL,
    created_at   TIMESTAMP                           DEFAULT NOW(),
    updated_at   TIMESTAMP                           DEFAULT NOW()
);
COMMENT ON TABLE volunteer.timesheet_detail IS $comment$Volunteer weekly timesheet details, list of start and end hours$comment$;

;

-- Timesheet view creation
CREATE MATERIALIZED VIEW volunteer.volunteer_timesheet_overview AS
WITH volunteer_area_affectation AS (SELECT vval.volunteer_id,
                                           STRING_AGG(va.area_name::TEXT, ', ' ORDER BY va.area_name ASC) AS volunteer_areas
                                    FROM volunteer.volunteer_area_lookup vval
                                             LEFT JOIN volunteer.area va ON vval.area_id = va.id
                                    GROUP BY vval.volunteer_id),
     volunteer_timesheet_summary AS (SELECT vt.volunteer_id,
                                            STRING_AGG(INITCAP( vtd.workday::TEXT) || ': ' ||
                                                       TO_CHAR( vtd.hour_start, 'HH24:MI')::TEXT || '-' ||
                                                       TO_CHAR( vtd.hour_end, 'HH24:MI')::TEXT ||
                                                       ' (' || TO_CHAR( (EXTRACT(epoch FROM vtd.hour_end - vtd.hour_start) / 3600 * INTERVAL '1 hour')::INTERVAL, 'HH24::MI') || ')', ', '
                                                       ORDER BY vtd.workday::TEXT ASC) AS working_timeslots,
                                            EXTRACT(epoch FROM SUM( vtd.hour_end - vtd.hour_start)) / 3600 AS weekly_hours
                                     FROM volunteer.timesheet vt
                                              LEFT JOIN volunteer.timesheet_detail vtd ON vt.id = vtd.timesheet_id
                                     GROUP BY vt.volunteer_id)
 SELECT
    vv.name,
    vv.surname,
    vt.description,
    vt.date_start,
    vt.date_end,
    vaa.volunteer_areas,
    vts.working_timeslots,
    vts.weekly_hours
FROM
    volunteer.volunteer vv
        LEFT JOIN volunteer.timesheet vt ON vv.id = vt.volunteer_id AND vt.status = 'active'::volunteer.timesheet_status
        LEFT JOIN volunteer_area_affectation vaa ON vv.id = vaa.volunteer_id
        LEFT JOIN volunteer_timesheet_summary vts ON vv.id = vts.volunteer_id;
COMMENT ON MATERIALIZED VIEW volunteer.volunteer_timesheet_overview IS $comment$Volunteer working times overview$comment$;

-- Timesheet display resource: https://www.jqueryscript.net/time-clock/pretty-weekly-event-calendar.html

-- Dummy data insertion
INSERT INTO volunteer.area( area_name)
VALUES
    ('administracion'::volunteer.area_name),
    ('bazar'::volunteer.area_name),
    ('cocina'::volunteer.area_name),
    ('lactantes'::volunteer.area_name),
    ('mantenimiento'::volunteer.area_name),
    ('maternal'::volunteer.area_name),
    ('preescolar'::volunteer.area_name),
    ('procuracion'::volunteer.area_name);

INSERT INTO volunteer.volunteer_area_lookup( volunteer_id, area_id)
VALUES
    ( (SELECT id FROM volunteer.volunteer WHERE email = 'josepabloha@live.com.mx'), ( SELECT id FROM volunteer.area WHERE area_name = 'preescolar')),
    ( (SELECT id FROM volunteer.volunteer WHERE email = 'josepabloha@live.com.mx'), ( SELECT id FROM volunteer.area WHERE area_name = 'maternal')),
    ( (SELECT id FROM volunteer.volunteer WHERE email = 'josepabloha2@live.com.mx'), ( SELECT id FROM volunteer.area WHERE area_name = 'maternal')),
    ( (SELECT id FROM volunteer.volunteer WHERE email = 'josepabloha3@live.com.mx'), ( SELECT id FROM volunteer.area WHERE area_name = 'lactantes'));

INSERT INTO volunteer.timesheet(volunteer_id, status, date_start, description)
VALUES
    (
        ( SELECT id FROM volunteer.volunteer WHERE email = 'josepabloha@live.com.mx'),
        'active'::volunteer.timesheet_status,
        CURRENT_DATE,
        'Jose Pablo work planing'
    ),
    (
        ( SELECT id FROM volunteer.volunteer WHERE email = 'josepabloha2@live.com.mx'),
        'active'::volunteer.timesheet_status,
        CURRENT_DATE,
        'Jose Pablo 2 work planing'
    ),
    (
        ( SELECT id FROM volunteer.volunteer WHERE email = 'josepabloha3@live.com.mx'),
        'active'::volunteer.timesheet_status,
        CURRENT_DATE,
        'Jose Pablo 3 work planing'
    );

INSERT INTO volunteer.timesheet_detail( timesheet_id, workday, hour_start, hour_end)
VALUES
    (
        ( SELECT id FROM volunteer.timesheet vt WHERE vt.status = 'active'::volunteer.timesheet_status AND vt.volunteer_id = ( SELECT id FROM volunteer.volunteer WHERE email = 'josepabloha@live.com.mx')),
        'monday'::volunteer.workday,
        '1300'::time,
        '1500'::time
    ),
    (
        ( SELECT id FROM volunteer.timesheet vt WHERE vt.status = 'active'::volunteer.timesheet_status AND vt.volunteer_id = ( SELECT id FROM volunteer.volunteer WHERE email = 'josepabloha@live.com.mx')),
        'tuesday'::volunteer.workday,
        '1600'::time,
        '1800'::time
    ),
    (
        ( SELECT id FROM volunteer.timesheet vt WHERE vt.status = 'active'::volunteer.timesheet_status AND vt.volunteer_id = ( SELECT id FROM volunteer.volunteer WHERE email = 'josepabloha2@live.com.mx')),
        'wednesday'::volunteer.workday,
        '1000'::time,
        '1200'::time
    ),
    (
        ( SELECT id FROM volunteer.timesheet vt WHERE vt.status = 'active'::volunteer.timesheet_status AND vt.volunteer_id = ( SELECT id FROM volunteer.volunteer WHERE email = 'josepabloha2@live.com.mx')),
        'thursday'::volunteer.workday,
        '1430'::time,
        '1800'::time
    ),
    (
        ( SELECT id FROM volunteer.timesheet vt WHERE vt.status = 'active'::volunteer.timesheet_status AND vt.volunteer_id = ( SELECT id FROM volunteer.volunteer WHERE email = 'josepabloha3@live.com.mx')),
        'friday'::volunteer.workday,
        '1100'::time,
        '1300'::time
    ),
    (
        ( SELECT id FROM volunteer.timesheet vt WHERE vt.status = 'active'::volunteer.timesheet_status AND vt.volunteer_id = ( SELECT id FROM volunteer.volunteer WHERE email = 'josepabloha3@live.com.mx')),
        'friday'::volunteer.workday,
        '1700'::time,
        '2000'::time
    );


REFRESH MATERIALIZED VIEW volunteer.volunteer_timesheet_overview;
REFRESH MATERIALIZED VIEW volunteer.volunteer_recruitment_overview;

-- Time logs management

DO $script$
    DECLARE
    BEGIN
        IF NOT EXISTS( SELECT * FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'users') THEN

            CREATE TYPE public.accesstype AS ENUM ('ENTRY', 'EXIT');

            -- ALTER TYPE public.accesstype OWNER TO testingdb_zcem_user;

            CREATE TABLE IF NOT EXISTS public.users
            (
                id                       SERIAL PRIMARY KEY,
                email                    VARCHAR(120) NOT NULL,
                password_hash            VARCHAR(255) NOT NULL,
                nombre_completo          VARCHAR(100) NOT NULL,
                apellidos                VARCHAR(100) NOT NULL,
                direccion                VARCHAR(255) NOT NULL,
                edad                     INTEGER      NOT NULL,
                telefono                 VARCHAR(20)  NOT NULL,
                role                     VARCHAR(20)  NOT NULL,
                is_authorized            BOOLEAN      NOT NULL,
                authorization_status     VARCHAR(20)  NOT NULL,
                authorization_info       TEXT         NOT NULL,
                foto_identificacion_path VARCHAR(255),
                created_at               TIMESTAMP    NOT NULL,
                authorized_at            TIMESTAMP,
                unauthorized_at          TIMESTAMP,
                authorized_by_id         INTEGER REFERENCES public.users,
                unauthorized_by_id       INTEGER REFERENCES public.users
            );

            -- ALTER TABLE public.users OWNER TO testingdb_zcem_user;

            CREATE INDEX IF NOT EXISTS ix_users_authorization_status
                ON public.users (authorization_status);

            CREATE INDEX IF NOT EXISTS ix_users_is_authorized
                ON public.users (is_authorized);

            CREATE UNIQUE INDEX ix_users_email
                ON public.users (email);

            CREATE INDEX IF NOT EXISTS ix_users_id
                ON public.users (id);

            CREATE INDEX IF NOT EXISTS ix_users_role
                ON public.users (role);

            CREATE TABLE IF NOT EXISTS public.qr_codes
            (
                id         SERIAL PRIMARY KEY,
                code       VARCHAR(255) NOT NULL,
                created_at TIMESTAMP    NOT NULL,
                expires_at TIMESTAMP    NOT NULL,
                is_active  BOOLEAN      NOT NULL
            );

            -- ALTER TABLE public.qr_codes OWNER TO testingdb_zcem_user;

            CREATE UNIQUE INDEX ix_qr_codes_code
                ON public.qr_codes (code);

            CREATE INDEX IF NOT EXISTS ix_qr_codes_id
                ON public.qr_codes (id);

            CREATE TABLE IF NOT EXISTS public.access_logs
            (
                id                 SERIAL
                    PRIMARY KEY,
                user_id            INTEGER    NOT NULL
                    REFERENCES public.users,
                qr_code_id         INTEGER    NOT NULL
                    REFERENCES public.qr_codes,
                access_type        ACCESSTYPE NOT NULL,
                timestamp          TIMESTAMP  NOT NULL,
                notes              TEXT,
                is_manual          BOOLEAN    NOT NULL,
                manual_by_admin_id INTEGER
                    REFERENCES public.users
            );

            -- ALTER TABLE public.access_logs OWNER TO testingdb_zcem_user;

            CREATE INDEX IF NOT EXISTS ix_access_logs_access_type
                ON public.access_logs (access_type);

            CREATE INDEX IF NOT EXISTS ix_access_logs_timestamp
                ON public.access_logs (timestamp);

            CREATE INDEX IF NOT EXISTS ix_access_logs_user_id
                ON public.access_logs (user_id);

            CREATE INDEX IF NOT EXISTS ix_access_logs_id
                ON public.access_logs (id);
        END IF;
    END;
$script$ LANGUAGE plpgsql;

INSERT INTO public.qr_codes (code, created_at, expires_at, is_active)
VALUES
    ('4db6bda418c2b32d8a8e7a7c26b9cb9fe2cc8d5febfa3a426f2c883d16148ca0', '2025-12-09 18:32:48.687002', '2025-12-09 18:37:48.686040', false),
    ('a9c5642384dbc57b288e4a8084c740b659b28b5e93985007c364d322e143a228', '2025-12-12 18:25:18.100077', '2025-12-12 18:30:18.099078', true)
ON CONFLICT (code) DO NOTHING;

-- Time tracking dummy data insertion
INSERT INTO public.users (email, password_hash, nombre_completo, apellidos, direccion, edad, telefono, role,
                          is_authorized, authorization_status, authorization_info, foto_identificacion_path, created_at,
                          authorized_at, unauthorized_at, authorized_by_id, unauthorized_by_id)
VALUES ('josepabloha@live.com.mx', '$2b$12$BKhkQIsd1N6wkY8f2eDSj.rgm77/a9CQFHeI0yph5RbXRJ8u94BUK', 'Jose Pablo',
        'Hernández Alono', 'PERU', 40, '2225251401', 'personal', TRUE, 'authorized',
        'Autorizado por Jose Pablo Hernández Alono el 09/12/2025 18:31', 'data/identificaciones/user_2_id.jpg',
        '2025-12-09 18:30:41.444678', '2025-12-09 18:31:44.330857', NULL, 1, NULL),
       ('josepabloha2@live.com.mx', '$2b$12$BKhkQIsd1N6wkY8f2eDSj.rgm77/a9CQFHeI0yph5RbXRJ8u94BUK', 'Jose Pablo2',
        'Hernández Alono2', 'PERU', 40, '2225251401', 'personal', TRUE, 'authorized',
        'Autorizado por Jose Pablo Hernández Alono el 09/12/2025 18:31', 'data/identificaciones/user_2_id.jpg',
        '2025-12-09 18:30:41.444678', '2025-12-09 18:31:44.330857', NULL, 1, NULL),
       ('josepabloha3@live.com.mx', '$2b$12$BKhkQIsd1N6wkY8f2eDSj.rgm77/a9CQFHeI0yph5RbXRJ8u94BUK', 'Jose Pablo3',
        'Hernández Alono3', 'PERU', 40, '2225251401', 'personal', TRUE, 'authorized',
        'Autorizado por Jose Pablo Hernández Alono el 09/12/2025 18:31', 'data/identificaciones/user_2_id.jpg',
        '2025-12-09 18:30:41.444678', '2025-12-09 18:31:44.330857', NULL, 1, NULL),
       ('josepabloha4@live.com.mx', '$2b$12$BKhkQIsd1N6wkY8f2eDSj.rgm77/a9CQFHeI0yph5RbXRJ8u94BUK', 'Jose Pablo4',
        'Hernández Alono4', 'PERU', 40, '2225251401', 'personal', TRUE, 'authorized',
        'Autorizado por Jose Pablo Hernández Alono el 09/12/2025 18:31', 'data/identificaciones/user_2_id.jpg',
        '2025-12-09 18:30:41.444678', '2025-12-09 18:31:44.330857', NULL, 1, NULL)
ON CONFLICT (email) DO NOTHING;

TRUNCATE TABLE public.access_logs;

INSERT INTO public.access_logs(user_id, qr_code_id, access_type, timestamp, is_manual)
VALUES ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'ENTRY',
        TO_TIMESTAMP('2025-11-03 13:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'EXIT',
        TO_TIMESTAMP('2025-11-03 15:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'ENTRY',
        TO_TIMESTAMP('2025-11-10 13:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'EXIT',
        TO_TIMESTAMP('2025-11-10 15:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'ENTRY',
        TO_TIMESTAMP('2025-11-17 13:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'EXIT',
        TO_TIMESTAMP('2025-11-17 15:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'ENTRY',
        TO_TIMESTAMP('2025-11-24 13:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'EXIT',
        TO_TIMESTAMP('2025-11-24 15:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'ENTRY',
        TO_TIMESTAMP('2025-11-04 16:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'EXIT',
        TO_TIMESTAMP('2025-11-04 18:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'ENTRY',
        TO_TIMESTAMP('2025-11-11 16:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'EXIT',
        TO_TIMESTAMP('2025-11-11 18:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'ENTRY',
        TO_TIMESTAMP('2025-11-18 16:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'EXIT',
        TO_TIMESTAMP('2025-11-18 18:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'ENTRY',
        TO_TIMESTAMP('2025-11-25 16:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'EXIT',
        TO_TIMESTAMP('2025-11-25 18:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha2@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'ENTRY',
        TO_TIMESTAMP('2025-11-05 10:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha2@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'EXIT',
        TO_TIMESTAMP('2025-11-05 12:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha2@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'ENTRY',
        TO_TIMESTAMP('2025-11-12 10:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha2@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'EXIT',
        TO_TIMESTAMP('2025-11-12 12:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha2@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'ENTRY',
        TO_TIMESTAMP('2025-11-19 10:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha2@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'EXIT',
        TO_TIMESTAMP('2025-11-19 12:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha2@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'ENTRY',
        TO_TIMESTAMP('2025-11-26 10:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha2@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'EXIT',
        TO_TIMESTAMP('2025-11-26 12:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha2@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'ENTRY',
        TO_TIMESTAMP('2025-11-06 14:30', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha2@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'EXIT',
        TO_TIMESTAMP('2025-11-06 18:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha2@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'ENTRY',
        TO_TIMESTAMP('2025-11-13 14:30', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha2@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'EXIT',
        TO_TIMESTAMP('2025-11-13 18:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha2@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'ENTRY',
        TO_TIMESTAMP('2025-11-20 14:30', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha2@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'EXIT',
        TO_TIMESTAMP('2025-11-20 18:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha2@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'ENTRY',
        TO_TIMESTAMP('2025-11-27 14:30', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha2@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'EXIT',
        TO_TIMESTAMP('2025-11-27 18:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha3@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'ENTRY',
        TO_TIMESTAMP('2025-11-07 11:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha3@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'EXIT',
        TO_TIMESTAMP('2025-11-07 13:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha3@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'ENTRY',
        TO_TIMESTAMP('2025-11-07 17:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha3@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'EXIT',
        TO_TIMESTAMP('2025-11-07 20:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha3@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'ENTRY',
        TO_TIMESTAMP('2025-11-14 11:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha3@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'EXIT',
        TO_TIMESTAMP('2025-11-14 13:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha3@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'ENTRY',
        TO_TIMESTAMP('2025-11-14 17:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha3@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'EXIT',
        TO_TIMESTAMP('2025-11-14 20:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha3@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'ENTRY',
        TO_TIMESTAMP('2025-11-21 11:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha3@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'EXIT',
        TO_TIMESTAMP('2025-11-21 13:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha3@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'ENTRY',
        TO_TIMESTAMP('2025-11-21 17:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha3@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'EXIT',
        TO_TIMESTAMP('2025-11-21 20:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha3@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'ENTRY',
        TO_TIMESTAMP('2025-11-28 11:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha3@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'EXIT',
        TO_TIMESTAMP('2025-11-28 13:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha3@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'ENTRY',
        TO_TIMESTAMP('2025-11-28 17:00', 'YYYY-MM-DD HH24:MI'),
        FALSE),
       ((SELECT id FROM public.users pu WHERE pu.email = 'josepabloha3@live.com.mx'),
        (SELECT id FROM qr_codes WHERE is_active = TRUE),
        'EXIT',
        TO_TIMESTAMP('2025-11-28 20:00', 'YYYY-MM-DD HH24:MI'),
        FALSE);
