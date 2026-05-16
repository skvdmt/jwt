package jwt

// Params Параметры токена.
type Params map[string]string

// Headers Параметры заголовков.
func Headers(options ...ParamsOption) *Params {
	return NewParams(options...)
}

// Claims Параметры клейм.
func Claims(options ...ParamsOption) *Params {
	return NewParams(options...)
}

// NewParams Конструктор параметров.
func NewParams(options ...ParamsOption) *Params {
	p := make(Params)
	for _, o := range options {
		o(p)
	}
	return &p
}

// ParamsOption Функциональная опция параметров.
type ParamsOption func(Params)

// Header Заголовок.
func Header(key, value string) ParamsOption {
	return Param(key, value)
}

// Claim Клейма.
func Claim(key, value string) ParamsOption {
	return Param(key, value)
}

// Param Конструктор параметра.
func Param(key, value string) ParamsOption {
	return func(p Params) {
		p[key] = value
	}
}
